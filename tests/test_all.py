import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import verify_tx
from verify_tx import parse, verify_input, verify, spk_for_address, vbytes
import sweeper
from sweeper import *

print("== A. verifier vs BIP143 spec vector ==")
raw="01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
spk1=bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
print("  native P2WPKH :", verify_input(parse(raw),1,spk1,600000000))
for label, r, v in (("tampered output", raw[:300]+("0" if raw[300]!="0" else "1")+raw[301:], 600000000), ("wrong amount", raw, 599999999)):
    try: verify_input(parse(r),1,spk1,v); print("  FAIL:", label, "not detected"); sys.exit(1)
    except ValueError as e: print(f"  {label} rejected ✓ ({e})")

print("== B. seeds / scheme detection ==")
from bip_utils import ElectrumV2MnemonicGenerator, ElectrumV1MnemonicGenerator, ElectrumV2MnemonicTypes
BIP = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
EL2S = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy(bytes(range(1,18))).ToStr()
EL2W = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT).FromEntropy(bytes(range(2,19))).ToStr()
EL1  = ElectrumV1MnemonicGenerator().FromEntropy(bytes(range(16))).ToStr()
assert seed_schemes(BIP)==["bip44","bip49","bip84","bip86","bip32h"]
assert seed_schemes(EL2S)==["el2std"] and seed_schemes(EL2W)==["el2sw"] and seed_schemes(EL1)==["el1"]
CUST = custom_scheme_id("m/0'/7'", None); assert CUST=="custom:m/0'/7':p2pkh"
assert custom_scheme_id("m/84'/0'/3'", None).endswith(":p2wpkh") and custom_scheme_id("m/0h/1h","p2tr")=="custom:m/0'/1':p2tr"
assert seed_schemes(BIP,[CUST])[-1]==CUST
for bad in ("44'/0'", "m/x", "m/0'/"):
    try: custom_scheme_id(bad,None); print("  FAIL",bad); sys.exit(1)
    except SystemExit: pass
print("  ✓")

print("== C. derivation vectors (BIP39 test mnemonic) ==")
R = Roots(BIP, "", seed_schemes(BIP))
vec = {("bip44",0,0,0):"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", ("bip49",0,0,0):"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
       ("bip84",0,0,0):"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", ("bip84",0,1,0):"bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
       ("bip86",0,0,0):"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"}   # BIP84/BIP86 spec vectors
for (s,a,c,i),want in vec.items():
    got,_ = R.derive(s,a,c,i); assert got==want, (s,got,want)
# account 1 differs from account 0; bip32h and custom derive something sane
assert R.derive("bip44",1,0,0)[0] != R.derive("bip44",0,0,0)[0]
assert R.derive("bip32h",0,0,0)[0].startswith("1")
R2 = Roots(BIP,"",[CUST]); assert R2.derive(CUST,0,0,0)[0].startswith("1")
# generic derivation == bip_utils' dedicated classes for m/0'/0/0
from bip_utils import Bip32Slip10Secp256k1, Bip39SeedGenerator, P2PKHAddrEncoder, CoinsConf
k = Bip32Slip10Secp256k1.FromSeed(Bip39SeedGenerator(BIP).Generate("")).DerivePath("m/0'/0/0")
assert R.derive("bip32h",0,0,0)[0] == P2PKHAddrEncoder.EncodeKey(k.PublicKey().KeyObject(), net_ver=CoinsConf.BitcoinMainNet.ParamByKey("p2pkh_net_ver"))
R.close(); R2.close()
print("  BIP44/49/84/86 vectors, accounts, bip32h, custom ✓")

print("== C2. public-only address list == private derivation, incl. accounts + custom ==")
for m in (BIP, EL2S, EL1):
    pub = list_addresses(m, "pw", 3, accounts=2, custom=[CUST] if m==BIP else ())
    R = Roots(m, "pw", seed_schemes(m, [CUST] if m==BIP else ()))
    for e in pub:
        got,_ = R.derive(e["scheme"], e["account"], e["chain"], e["index"]); assert got==e["address"], e
    R.close()
    if m == BIP:
        assert any(e["account"]==1 for e in pub if e["scheme"]=="bip44") and any(e["scheme"]==CUST for e in pub)
print("  all match ✓")

print("== D. sign every input type and verify independently ==")
DEST="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
_ctr=[0]
def coins_for(m, pw, items, custom=()):   # items: (scheme, account, chain, index, value)
    out=[]; R=Roots(m,pw,seed_schemes(m,custom))
    for (s,a,ch,ix,val) in items:
        _ctr[0]+=1; addr,priv=R.derive(s,a,ch,ix); info=scheme_info(s)
        out.append(Coin(bytes([_ctr[0]]*32).hex(),0,val,addr,info["kind"],priv,path_str(s,a,ch,ix),not info["uncompressed"]))
    R.nodes.clear(); return out
coins = coins_for(BIP,"",[("bip44",0,0,0,100000),("bip49",0,1,2,100000),("bip84",0,0,5,100000),("bip84",0,0,5,70000),
                          ("bip86",0,0,0,100000),("bip86",1,1,3,100000),("bip32h",0,0,1,100000),(CUST,0,0,0,100000)],[CUST]) \
      + coins_for(EL2S,"Pw",[("el2std",0,0,1,100000)]) + coins_for(EL2W,"",[("el2sw",0,1,0,100000)]) + coins_for(EL1,"",[("el1",0,0,0,100000)])
prevouts=[{"script_pubkey": spk_for_address(c.address).hex(), "value": c.value} for c in coins]
tx,send,fee,vb,_,_,_ = build_and_sign(coins, DEST, 7)
kinds = verify(tx.serialize(), prevouts)
print("  verified inputs:", kinds)
assert kinds == ['p2pkh','p2sh-p2wpkh','p2wpkh','p2wpkh','p2tr','p2tr','p2pkh','p2pkh','p2pkh','p2wpkh','p2pkh-uncompressed']
assert all(not any(c.priv) for c in coins), "keys zeroed"
est = estimate_vbytes(coins); real = vbytes(tx.serialize()); assert est >= real and vb == real
print(f"  fee estimate {est} vB >= actual {real} vB ✓")
# taproot destination
c = coins_for(BIP,"",[("bip84",0,0,9,50000)])
tx,*_ = build_and_sign(c, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", 3)
assert parse(tx.serialize())["outs"][0]["spk"][:2]==b"\x51\x20"; print("  taproot destination ✓")

print("== D2. self-check inside build_and_sign refuses a bad tx ==")
orig = verify_tx.verify
verify_tx.verify = lambda *a, **k: (_ for _ in ()).throw(ValueError("forced"))
try: build_and_sign(coins_for(BIP,"",[("bip84",0,0,0,100000)]), DEST, 5); print("  FAIL"); sys.exit(1)
except SystemExit as e: assert "INTERNAL ERROR" in str(e); print("  refused ✓")
verify_tx.verify = orig

print("== D3. --test / --amount partial send ==")
coins = coins_for(BIP,"",[("bip84",0,0,0,30000),("bip44",0,0,1,200000),("bip49",0,0,2,50000)]); allc=list(coins)
tx,send,fee,vb,change,change_addr,used = build_and_sign(coins, DEST, 5, parse_amount("0.0001"))
assert send==10000 and len(used)==1 and used[0].value==200000 and change_addr==used[0].address and change==200000-10000-fee
verify(tx.serialize(), [{"script_pubkey": spk_for_address(c.address).hex(), "value": c.value} for c in used])
ptx=parse(tx.serialize()); assert ptx["outs"][1]["spk"]==spk_for_address(change_addr) and ptx["outs"][1]["value"]==change
assert all(any(c.priv) for c in allc if c not in used); print("  1 input used, change back to old address, others untouched ✓")
c1 = coins_for(BIP,"",[("bip84",0,0,3,10600)]); tx,send,fee,vb,change,change_addr,used = build_and_sign(c1, DEST, 1, 10000)
assert change==0 and change_addr is None and len(parse(tx.serialize())["outs"])==1; print("  dust change folded into fee ✓")
c3 = coins_for(BIP,"",[("bip84",0,0,4,6000),("bip84",0,0,5,6000),("bip84",0,0,6,6000)])
tx,send,fee,vb,change,change_addr,used = build_and_sign(c3, DEST, 1, 10000); assert len(used)==2; print("  selects 2 of 3 ✓")
try: build_and_sign(coins_for(BIP,"",[("bip84",0,0,7,5000)]), DEST, 1, 10000); print("  FAIL"); sys.exit(1)
except SystemExit as e: assert "Not enough funds" in str(e)
for bad in ("0.000001","abc","0"):
    try: parse_amount(bad); print("  FAIL", bad); sys.exit(1)
    except SystemExit: pass
assert parse_amount("0.0001")==10000; print("  insufficient funds / amount parsing ✓")

print("== E. negative: original bug (P2WPKH spk as script code) and taproot tamper are caught ==")
from bitcoinutils.keys import PrivateKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
c = coins_for(BIP,"",[("bip84",0,0,0,100000)])[0]
pk=PrivateKey(b=bytes(c.priv)); pub=pk.get_public_key()
t=Transaction([TxInput(c.txid,c.vout)],[TxOutput(90000,sweeper._dest_script(DEST))],has_segwit=True)
t.witnesses.append(TxWitnessInput([pk.sign_segwit_input(t,0,pub.get_segwit_address().to_script_pub_key(),c.value),pub.to_hex()]))
try: verify(t.serialize(),[{"script_pubkey":spk_for_address(c.address).hex(),"value":c.value}]); print("  FAIL"); sys.exit(1)
except ValueError as e: print(f"  wrong script code caught ✓ ({e})")
c = coins_for(BIP,"",[("bip86",0,0,0,100000)])
tx,*_ = build_and_sign(c, DEST, 2); h=tx.serialize()
for label, r, val in (("tampered output", h[:120]+("0" if h[120]!="0" else "1")+h[121:], 100000), ("wrong amount", h, 99999)):
    try: verify(r,[{"script_pubkey":spk_for_address(c[0].address).hex(),"value":val}]); print("  FAIL", label); sys.exit(1)
    except ValueError as e: print(f"  taproot {label} caught ✓ ({e})")

print("== H. WIF private keys ==")
WC="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"   # privkey = 1, compressed
WU="5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"    # privkey = 1, uncompressed
assert looks_like_wif_list(WC) and looks_like_wif_list(f"{WC}, {WU}") and not looks_like_wif_list(BIP) and not looks_like_wif_list(WC[:-1]+"0")
assert seed_schemes(WC)==["wif:p2pkh","wif:p2sh-p2wpkh","wif:p2wpkh","wif:p2tr"]
R=Roots(f"{WC} {WU}","",seed_schemes(WC))
assert R.derive("wif:p2pkh",0,0,0)[0]=="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"      # well-known vectors for k=1
assert R.derive("wif:p2pkh",0,0,1)[0]=="1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
assert R.derive("wif:p2wpkh",0,0,0)[0]=="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP173 example (k=1)
assert R.derive("wif:p2wpkh",0,0,1)==(None,None) and R.derive("wif:p2pkh",0,1,0)==(None,None) and R.derive("wif:p2pkh",0,0,2)==(None,None)
assert R.compressed("wif:p2pkh",0) and not R.compressed("wif:p2pkh",1)
assert int.from_bytes(bytes(R.derive("wif:p2pkh",0,0,0)[1]),"big")==1
R.close(); assert R.wifs==[]
pub = list_addresses(f"{WC} {WU}","",100)
assert len(pub)==5 and {e["address"] for e in pub} >= {"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH","1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}
print("  vectors, finite listing (5 addrs for 2 keys), key wiping ✓")
# sign all 5 WIF address types in one tx and verify independently
coins=[]
for e in pub:
    _ctr[0]+=1; k=keys_for(f"{WC} {WU}","",{e["address"]:{x:e[x] for x in ("scheme","account","chain","index")}})
    kind,path,priv,comp=k[e["address"]]; coins.append(Coin(bytes([_ctr[0]]*32).hex(),0,60000,e["address"],kind,priv,path,comp))
tx,*_ = build_and_sign(coins, DEST, 3)
kinds=verify(tx.serialize(), [{"script_pubkey":spk_for_address(c.address).hex(),"value":c.value} for c in coins])
assert sorted(kinds)==sorted(["p2pkh","p2pkh-uncompressed","p2sh-p2wpkh","p2wpkh","p2tr"]), kinds
print("  signed 5 WIF-derived inputs (incl. uncompressed) and verified ✓", kinds)
k=keys_for(f"{WC} {WU}","",{"1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm":None}); assert not k["1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"][3]
try: Roots(WC[:-1]+"1","",["wif:p2pkh"]); print("  FAIL"); sys.exit(1)
except SystemExit as e: assert "Invalid private key" in str(e)
print("  search by address, bad checksum rejected ✓")

print("== F. fee-rate validation ==")
for bad in (0,-5,None,"10",2.5):
    try: check_fee_rate(bad); print("  FAIL", bad); sys.exit(1)
    except SystemExit: pass
print("  ✓")

print("== G. keys_for: exact location, search, accounts, custom, string entries, dedupe ==")
e = [x for x in list_addresses(BIP,"",3,accounts=2,custom=[CUST]) if x["scheme"]=="bip44" and x["account"]==1][2]
k = keys_for(BIP,"",{e["address"]:{k:e[k] for k in ("scheme","account","chain","index")}}); assert k[e["address"]][1]==e["path"]
try: keys_for(BIP,"",{e["address"]:None}, max_index=10, accounts=1); print("  FAIL"); sys.exit(1)
except SystemExit as ex: assert "accounts" in str(ex)
k2 = keys_for(BIP,"",{e["address"]:None}, max_index=10, accounts=2); assert e["address"] in k2
ec = [x for x in list_addresses(BIP,"",2,custom=[CUST]) if x["scheme"]==CUST][1]
k3 = keys_for(BIP,"",{ec["address"]:{k:ec[k] for k in ("scheme","account","chain","index")}}); assert ec["address"] in k3   # custom id carried in file, no --path needed
k4 = keys_for(BIP,"",{ec["address"]:None}, max_index=5, custom=[CUST]); assert ec["address"] in k4
n = normalize_addr_entries(["1A","1A",{"address":"1A","scheme":"bip44","chain":0,"index":1},"1B"]); assert len(n)==2 and any(len(x)==4 for x in n)
print("  ✓")
print("\nALL TESTS PASSED")
