#!/usr/bin/env python3
"""
verify_tx.py — independent signature verifier for transactions produced by sweeper.py.

Deliberately shares NO code with the signing path: it parses the raw hex itself,
recomputes the legacy (pre-segwit) and BIP143 sighash from the specs, and checks
each signature with libsecp256k1 (coincurve). If this says a transaction is valid,
the network will accept its signatures.

Usage (library):
    from verify_tx import verify
    verify(raw_hex, [{"script_pubkey": hex, "value": sats}, ...])   # raises on failure
"""
import hashlib
import struct

import coincurve

SIGHASH_ALL = 1


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


# ----------------------------------------------------------------------------- parsing

class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        v = self.b[self.i:self.i + n]
        if len(v) != n:
            raise ValueError("truncated")
        self.i += n
        return v

    def u8(self):  return self.take(1)[0]
    def u32(self): return struct.unpack("<I", self.take(4))[0]
    def u64(self): return struct.unpack("<Q", self.take(8))[0]

    def varint(self):
        n = self.u8()
        if n < 0xfd: return n
        if n == 0xfd: return struct.unpack("<H", self.take(2))[0]
        if n == 0xfe: return self.u32()
        return self.u64()

    def varbytes(self):
        return self.take(self.varint())


def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b):
    return varint(len(b)) + b


def parse(raw):
    r = Reader(bytes.fromhex(raw))
    version = r.u32()
    segwit = r.b[r.i:r.i + 2] == b"\x00\x01"
    if segwit:
        r.take(2)
    ins = []
    for _ in range(r.varint()):
        ins.append({"prev_hash": r.take(32), "index": r.u32(), "script_sig": r.varbytes(), "seq": r.u32()})
    outs = []
    for _ in range(r.varint()):
        outs.append({"value": r.u64(), "spk": r.varbytes()})
    if segwit:
        for tin in ins:
            tin["witness"] = [r.varbytes() for _ in range(r.varint())]
    else:
        for tin in ins:
            tin["witness"] = []
    locktime = r.u32()
    if r.i != len(r.b):
        raise ValueError("trailing bytes")
    return {"version": version, "ins": ins, "outs": outs, "locktime": locktime}


# ----------------------------------------------------------------------------- script helpers

def push(data):
    n = len(data)
    if n < 0x4c: return bytes([n]) + data
    if n <= 0xff: return b"\x4c" + bytes([n]) + data
    raise ValueError("push too large")


def parse_pushes(script):
    """Return the list of pushed data items in a push-only script."""
    r, out = Reader(script), []
    while r.i < len(r.b):
        op = r.u8()
        if 1 <= op <= 0x4b: out.append(r.take(op))
        elif op == 0x4c: out.append(r.take(r.u8()))
        elif op == 0x4d: out.append(r.take(struct.unpack("<H", r.take(2))[0]))
        elif op == 0: out.append(b"")
        else: raise ValueError(f"non-push opcode {op:#x} in scriptSig")
    return out


def p2pkh_script(h160):
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def classify(spk):
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh", spk[3:23]
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87:
        return "p2sh", spk[2:22]
    if len(spk) == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh", spk[2:]
    if len(spk) == 34 and spk[:2] == b"\x51\x20":
        return "p2tr", spk[2:]
    raise ValueError(f"unsupported scriptPubKey {spk.hex()}")


# ----------------------------------------------------------------------------- sighash

def _serialize_outs(tx):
    return b"".join(struct.pack("<Q", o["value"]) + varbytes(o["spk"]) for o in tx["outs"])


def legacy_sighash(tx, idx, script_code):
    b = struct.pack("<I", tx["version"]) + varint(len(tx["ins"]))
    for i, tin in enumerate(tx["ins"]):
        b += tin["prev_hash"] + struct.pack("<I", tin["index"])
        b += varbytes(script_code if i == idx else b"")
        b += struct.pack("<I", tin["seq"])
    b += varint(len(tx["outs"])) + _serialize_outs(tx)
    b += struct.pack("<I", tx["locktime"]) + struct.pack("<I", SIGHASH_ALL)
    return sha256d(b)


def bip143_sighash(tx, idx, script_code, value):
    hash_prevouts = sha256d(b"".join(t["prev_hash"] + struct.pack("<I", t["index"]) for t in tx["ins"]))
    hash_sequence = sha256d(b"".join(struct.pack("<I", t["seq"]) for t in tx["ins"]))
    hash_outputs = sha256d(_serialize_outs(tx))
    tin = tx["ins"][idx]
    b = (struct.pack("<I", tx["version"]) + hash_prevouts + hash_sequence
         + tin["prev_hash"] + struct.pack("<I", tin["index"])
         + varbytes(script_code) + struct.pack("<Q", value) + struct.pack("<I", tin["seq"])
         + hash_outputs + struct.pack("<I", tx["locktime"]) + struct.pack("<I", SIGHASH_ALL))
    return sha256d(b)


def bip341_sighash(tx, idx, prevouts, hash_type):
    """BIP341 key-path sighash, no annex. prevouts: [(spk_bytes, value)] for ALL inputs."""
    if hash_type not in (0x00, 0x01):
        raise ValueError("only SIGHASH_DEFAULT / SIGHASH_ALL supported")
    sha = lambda b: hashlib.sha256(b).digest()
    sha_prevouts = sha(b"".join(t["prev_hash"] + struct.pack("<I", t["index"]) for t in tx["ins"]))
    sha_amounts = sha(b"".join(struct.pack("<Q", v) for _, v in prevouts))
    sha_spks = sha(b"".join(varbytes(s) for s, _ in prevouts))
    sha_sequences = sha(b"".join(struct.pack("<I", t["seq"]) for t in tx["ins"]))
    sha_outputs = sha(_serialize_outs(tx))
    msg = (b"\x00" + bytes([hash_type]) + struct.pack("<I", tx["version"]) + struct.pack("<I", tx["locktime"])
           + sha_prevouts + sha_amounts + sha_spks + sha_sequences + sha_outputs
           + b"\x00"                       # spend_type: key path, no annex
           + struct.pack("<I", idx))
    return tagged_hash("TapSighash", msg)


# ----------------------------------------------------------------------------- verification

def _check_sig(sig_with_type, pubkey, digest):
    if sig_with_type[-1] != SIGHASH_ALL:
        raise ValueError("sighash type is not SIGHASH_ALL")
    der = sig_with_type[:-1]
    # strict DER + low-S are policy rules; coincurve's verify uses libsecp256k1 which
    # requires strict DER already. Check low-S explicitly.
    r_len = der[3]
    s_len = der[5 + r_len]
    s = int.from_bytes(der[6 + r_len:6 + r_len + s_len], "big")
    if s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0:
        raise ValueError("high-S signature (non-standard)")
    if not coincurve.PublicKey(pubkey).verify(der, digest, hasher=None):
        raise ValueError("signature does not verify")


def verify_input(tx, idx, spk, value, prevouts=None):
    """prevouts (all inputs, [(spk, value)]) is required only for taproot inputs."""
    kind, h = classify(spk)
    tin = tx["ins"][idx]
    if kind == "p2tr":
        if tin["script_sig"] or len(tin["witness"]) != 1:
            raise ValueError("p2tr: expected empty scriptSig and a 1-item witness (key path)")
        sig = tin["witness"][0]
        if len(sig) == 64:
            hash_type = 0x00
        elif len(sig) == 65 and sig[64] == 0x01:
            hash_type = 0x01
        else:
            raise ValueError("p2tr: signature must be 64 bytes (default) or 65 with SIGHASH_ALL")
        if prevouts is None:
            raise ValueError("p2tr: prevouts for all inputs required")
        digest = bip341_sighash(tx, idx, prevouts, hash_type)
        if not coincurve.PublicKeyXOnly(h).verify(sig[:64], digest):
            raise ValueError("p2tr: schnorr signature does not verify")
        return "p2tr"
    if kind == "p2pkh":
        items = parse_pushes(tin["script_sig"])
        if len(items) != 2 or tin["witness"]:
            raise ValueError("p2pkh: expected <sig> <pubkey> and no witness")
        sig, pub = items
        if hash160(pub) != h:
            raise ValueError("p2pkh: pubkey hash does not match scriptPubKey")
        _check_sig(sig, pub, legacy_sighash(tx, idx, spk))
        return "p2pkh" + ("" if len(pub) == 33 else "-uncompressed")
    if kind == "p2wpkh":
        if tin["script_sig"] or len(tin["witness"]) != 2:
            raise ValueError("p2wpkh: expected empty scriptSig and 2-item witness")
        sig, pub = tin["witness"]
        if len(pub) != 33 or hash160(pub) != h:
            raise ValueError("p2wpkh: pubkey (must be compressed) hash does not match")
        _check_sig(sig, pub, bip143_sighash(tx, idx, p2pkh_script(h), value))
        return "p2wpkh"
    if kind == "p2sh":
        items = parse_pushes(tin["script_sig"])
        if len(items) != 1:
            raise ValueError("p2sh: expected exactly one push (the redeem script)")
        redeem = items[0]
        if hash160(redeem) != h:
            raise ValueError("p2sh: redeem script hash does not match scriptPubKey")
        rkind, rh = classify(redeem)
        if rkind != "p2wpkh":
            raise ValueError("p2sh: only P2SH-P2WPKH is supported")
        if len(tin["witness"]) != 2:
            raise ValueError("p2sh-p2wpkh: expected 2-item witness")
        sig, pub = tin["witness"]
        if len(pub) != 33 or hash160(pub) != rh:
            raise ValueError("p2sh-p2wpkh: pubkey hash does not match redeem script")
        _check_sig(sig, pub, bip143_sighash(tx, idx, p2pkh_script(rh), value))
        return "p2sh-p2wpkh"


def verify(raw_hex, prevouts):
    """prevouts: list aligned with inputs, each {"script_pubkey": hex, "value": sats}.
    Returns list of input kinds. Raises ValueError describing the first failure."""
    tx = parse(raw_hex)
    if len(prevouts) != len(tx["ins"]):
        raise ValueError("prevouts count != inputs")
    seen = set()
    for tin in tx["ins"]:
        k = (tin["prev_hash"], tin["index"])
        if k in seen:
            raise ValueError("duplicate input")
        seen.add(k)
    total_in = sum(p["value"] for p in prevouts)
    total_out = sum(o["value"] for o in tx["outs"])
    if total_out > total_in:
        raise ValueError("outputs exceed inputs")
    allp = [(bytes.fromhex(p["script_pubkey"]), p["value"]) for p in prevouts]
    kinds = []
    for i, (spk, value) in enumerate(allp):
        kinds.append(verify_input(tx, i, spk, value, allp))
    return kinds


def _b58decode(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in s:
        n = n * 58 + alphabet.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    raw = b"\x00" * pad + raw
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        raise ValueError("bad base58 checksum")
    return raw[:-4]


def _bech32_decode(addr):
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    hrp, data = addr.lower().rsplit("1", 1)
    vals = [CHARSET.index(c) for c in data]

    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                chk ^= GEN[i] if (top >> i) & 1 else 0
        return chk
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = polymod(hrp_exp + vals)
    ver, prog5 = vals[0], vals[1:-6]
    # BIP173 bech32 for witness v0, BIP350 bech32m for v1+
    if (ver == 0 and const != 1) or (ver != 0 and const != 0x2bc830a3):
        raise ValueError("bad bech32/bech32m checksum")
    acc, bits, out = 0, 0, bytearray()
    for v in prog5:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    return ver, bytes(out)


def vbytes(raw_hex):
    """Virtual size per BIP141: (3*base_size + total_size) / 4, rounded up."""
    b = bytes.fromhex(raw_hex)
    tx = parse(raw_hex)
    total = len(b)
    if any(t["witness"] for t in tx["ins"]):
        # base = total minus marker/flag (2) minus all witness bytes
        wit = 0
        for t in tx["ins"]:
            wit += len(varint(len(t["witness"]))) + sum(len(varbytes(w)) for w in t["witness"])
        base = total - 2 - wit
    else:
        base = total
    return (3 * base + total + 3) // 4


def spk_for_address(addr):
    """scriptPubKey for a 1.../3.../bc1q... address, computed here without bitcoinutils."""
    if addr.startswith("bc1"):
        ver, prog = _bech32_decode(addr)
        if ver == 0:
            return bytes([0, len(prog)]) + prog
        if ver == 1 and len(prog) == 32:
            return b"\x51\x20" + prog
        raise ValueError("unsupported witness version/program")
    raw = _b58decode(addr)
    if raw[0] == 0x00:
        return p2pkh_script(raw[1:])
    if raw[0] == 0x05:
        return b"\xa9\x14" + raw[1:] + b"\x87"
    raise ValueError("unknown address version")
