"""Synthetic success and explicit malformed-input demonstration."""
import json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parent
for c in json.loads((ROOT/"smoke.json").read_text()):
    r=subprocess.run([sys.executable,str(ROOT/"pcap_flow_ledger.py"),*c["args"]],cwd=ROOT,capture_output=True,text=True)
    assert r.returncode==c["exit"],r.stdout+r.stderr
    data=json.loads(r.stdout)
    for k,v in c.get("expect",{}).items():assert data[k]==v,data
    if c["exit"]==2:assert "error" in data,data
    print(r.stdout.strip())
