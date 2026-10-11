"""Core regressions, compilation, example and fresh installed CLI outside source."""
import json,pathlib,subprocess,sys,tempfile,venv
ROOT=pathlib.Path(__file__).resolve().parent
subprocess.run([sys.executable,"-m","unittest","discover","-v"],cwd=ROOT,check=True)
subprocess.run([sys.executable,"-m","compileall","-q","pcap_flow_ledger.py"],cwd=ROOT,check=True)
subprocess.run([sys.executable,"demo.py"],cwd=ROOT,check=True)
with tempfile.TemporaryDirectory() as tmp:
    temp=pathlib.Path(tmp);wheel=temp/"wheels";wheel.mkdir()
    subprocess.run([sys.executable,"-m","pip","wheel","--no-deps","--no-build-isolation","--wheel-dir",str(wheel),str(ROOT)],check=True)
    env=temp/"env";venv.EnvBuilder(with_pip=True).create(env)
    py=env/("Scripts/python.exe" if sys.platform=="win32" else "bin/python")
    package=list(wheel.glob("*.whl"));assert len(package)==1
    subprocess.run([str(py),"-m","pip","install","--no-index","--no-deps",str(package[0])],check=True)
    cmd=env/("Scripts/pcap-flow-ledger.exe" if sys.platform=="win32" else "bin/pcap-flow-ledger")
    for case in json.loads((ROOT/"smoke.json").read_text()):
        args=[str(ROOT/x) if (ROOT/x).is_file() else x for x in case["args"]]
        r=subprocess.run([str(cmd),*args],cwd=temp,capture_output=True,text=True)
        assert r.returncode==case["exit"],r.stdout+r.stderr
        result=json.loads(r.stdout)
        if case["exit"]==2:assert "error" in result,result
        for k,v in case.get("expect",{}).items():assert result[k]==v,result
    print("PASS: clean wheel install and installed success/failure CLI outside source")
