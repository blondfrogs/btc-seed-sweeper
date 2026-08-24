import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import sys, json, io, contextlib
import verify_tx
from verify_tx import parse, verify_input, verify, spk_for_address
import sweeper
from sweeper import *

print("== A. verifier vs BIP143 spec vectors ==")
raw="01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
print("  native P2WPKH :", verify_input(parse(raw),1,bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),600000000))
spk1=bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
for label, r, v in (("tampered output", raw[:300]+("0" if raw[300]!="0" else "1")+raw[301:], 600000000), ("wrong amount", raw, 599999999)):
    try: verify_input(parse(r),1,spk1,v); print("  FAIL:", label, "not detected"); sys.exit(1)
    except ValueError as e: print(f"  {label} rejected ✓ ({e})")

print("== B. seeds for every scheme ==")
from bip_utils import ElectrumV2MnemonicGenerator, ElectrumV1MnemonicGenerator, ElectrumV2MnemonicTypes
BIP = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
EL2S = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.STANDARD).FromEntropy(bytes(range(1,18))).ToStr()
EL2W = ElectrumV2MnemonicGenerator(ElectrumV2MnemonicTypes.SEGWIT).FromEntropy(bytes(range(2,19))).ToStr()
EL1  = ElectrumV1MnemonicGenerator().FromEntropy(bytes(range(16))).ToStr()
for name,m in (("BIP39",BIP),("El2 std",EL2S),("El2 segwit",EL2W),("El1",EL1)):
    print(f"  {name:10s} schemes={seed_schemes(m)}")
assert seed_schemes(EL2S)==["el2std"] and seed_schemes(EL2W)==["el2sw"], "electrum type detection"

print("== C. public-only address list == private derivation ==")
for m in (BIP, EL2S, EL1):
    pub = list_addresses(m, "pw", 3)
    for e in pub:
        got,_ = sweeper._derive(sweeper._roots(m,"pw",[e["scheme"]],False)[e["scheme"]], e["scheme"], e["chain"], e["index"], False)
        assert got==e["address"], (e, got)
print("  all match ✓")

print("== D. sign every input type and verify independently ==")
DEST="bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
_ctr=[0]
def coins_for(m, pw, items):   # items: (scheme, chain, index, value)
    out=[]; 
    for n,(s,ch,ix,val) in enumerate(items):
        roots=sweeper._roots(m,pw,[s],False); addr,priv=sweeper._derive(roots[s],s,ch,ix,False)
        label,kind,comp=SCHEMES[s]; out.append(Coin(bytes([_ctr.__setitem__(0,_ctr[0]+1) or _ctr[0]]*32).hex(),n,val,addr,kind,priv,path_str(s,ch,ix),comp))
    return out
coins = coins_for(BIP,"",[("bip44",0,0,100000),("bip49",1,2,100000),("bip84",0,5,100000),("bip84",0,5,70000)]) \
      + coins_for(EL2S,"Pw",[("el2std",0,1,100000)]) + coins_for(EL2W,"",[("el2sw",1,0,100000)]) + coins_for(EL1,"",[("el1",0,0,100000)])
prevouts=[{"script_pubkey": spk_for_address(c.address).hex(), "value": c.value} for c in coins]
tx,send,fee,vb,_,_,_ = build_and_sign(coins, DEST, 7)
kinds = verify(tx.serialize(), prevouts)
print("  verified inputs:", kinds)
assert all(not any(c.priv) for c in coins), "keys zeroed"
from verify_tx import vbytes
est = estimate_vbytes(coins); real = vbytes(tx.serialize())
assert est >= real, (est, real)
print(f"  fee estimate {est} vB >= actual {real} vB ✓ (fee charged on actual size)")
assert vb == real

print("== D2. self-check inside build_and_sign refuses a bad tx ==")
orig = verify_tx.verify
verify_tx.verify = lambda *a, **k: (_ for _ in ()).throw(ValueError("forced"))
try: build_and_sign(coins_for(BIP,"",[("bip84",0,0,100000)]), DEST, 5); print("  FAIL"); sys.exit(1)
except SystemExit as e: assert "INTERNAL ERROR" in str(e); print("  refused ✓")
verify_tx.verify = orig

print("== E. negative: the ORIGINAL bug (P2WPKH spk as script code) must be caught ==")
from bitcoinutils.keys import PrivateKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
c = coins_for(BIP,"",[("bip84",0,0,100000)])[0]; c.txid="ab"*32
pk=PrivateKey(b=bytes(c.priv)); pub=pk.get_public_key()
t=Transaction([TxInput(c.txid,c.vout)],[TxOutput(90000,sweeper._dest_script(DEST))],has_segwit=True)
sig=pk.sign_segwit_input(t,0,pub.get_segwit_address().to_script_pub_key(),c.value)   # <- wrong script code
t.witnesses.append(TxWitnessInput([sig,pub.to_hex()]))
try: verify(t.serialize(),[{"script_pubkey":spk_for_address(c.address).hex(),"value":c.value}]); print("  FAIL: bug not caught"); sys.exit(1)
except ValueError as e: print(f"  caught ✓ ({e})")

print("== D3. --test / --amount partial send ==")
coins = coins_for(BIP,"",[("bip84",0,0,30000),("bip44",0,1,200000),("bip49",0,2,50000)])
allc = list(coins)
tx,send,fee,vb,change,change_addr,used = build_and_sign(coins, DEST, 5, parse_amount("0.0001"))
assert send==10000 and len(used)==1 and used[0].value==200000, "largest single input should cover it"
assert change_addr==used[0].address and change==200000-10000-fee, (change, fee)
prev=[{"script_pubkey": spk_for_address(c.address).hex(), "value": c.value} for c in used]
verify(tx.serialize(), prev)
ptx=parse(tx.serialize()); assert len(ptx["outs"])==2
assert ptx["outs"][0]["spk"]==spk_for_address(DEST) and ptx["outs"][0]["value"]==10000
assert ptx["outs"][1]["spk"]==spk_for_address(change_addr) and ptx["outs"][1]["value"]==change
untouched=[c for c in allc if c not in used]; assert len(untouched)==2 and all(any(c.priv) for c in untouched)
print(f"  1 input used, change {change} sats back to old address, 2 coins untouched (keys intact) ✓")
# dust change: amount nearly equals the only input
c1 = coins_for(BIP,"",[("bip84",0,3,10600)])   # change would be ~435 sats < dust
tx,send,fee,vb,change,change_addr,used = build_and_sign(c1, DEST, 1, 10000)
assert change==0 and change_addr is None and len(parse(tx.serialize())["outs"])==1
verify(tx.serialize(), [{"script_pubkey": spk_for_address(c1[0].address).hex(), "value": 10600}])
print("  dust change folded into fee, single output ✓")
# multi-input selection
c3 = coins_for(BIP,"",[("bip84",0,4,6000),("bip84",0,5,6000),("bip84",0,6,6000)])
tx,send,fee,vb,change,change_addr,used = build_and_sign(c3, DEST, 1, 10000)
assert len(used)==2; verify(tx.serialize(), [{"script_pubkey": spk_for_address(c.address).hex(), "value": c.value} for c in used])
print("  needs 2 of 3 inputs -> selects 2 ✓")
try: build_and_sign(coins_for(BIP,"",[("bip84",0,7,5000)]), DEST, 1, 10000); print("  FAIL"); sys.exit(1)
except SystemExit as e: assert "Not enough funds" in str(e); print("  insufficient funds refused ✓")
for bad in ("0.000001","abc","0"):
    try: parse_amount(bad); print("  FAIL", bad); sys.exit(1)
    except SystemExit: pass
assert parse_amount("0.0001")==10000 and parse_amount("1")==100000000
print("  amount parsing ✓")

print("== F. fee-rate validation ==")
for bad in (0,-5,None,"10",2.5):
    try: check_fee_rate(bad); print("  FAIL", bad); sys.exit(1)
    except SystemExit: pass
print("  0/-5/None/'10'/2.5 all rejected ✓")

print("== G. keys_for: exact path vs search, string entries, dedupe ==")
e = list_addresses(BIP,"",3)[5]
k = keys_for(BIP,"",{e["address"]:{"scheme":e["scheme"],"chain":e["chain"],"index":e["index"]}})
assert e["address"] in k and k[e["address"]][1]==e["path"]
k2 = keys_for(BIP,"",{e["address"]:None}, max_index=10); assert e["address"] in k2
try: keys_for(BIP,"",{e["address"]:None}, max_index=1); print("  FAIL"); sys.exit(1)
except SystemExit as ex: assert "max-index" in str(ex)
n = normalize_addr_entries(["1A","1A",{"address":"1A","scheme":"bip44","chain":0,"index":1},"1B"])
assert len(n)==2 and any(len(x)==4 for x in n)
print("  ✓")
print("\nALL TESTS PASSED")
