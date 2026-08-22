"""阶段测试：detector + waf + fingerprint 在 DVWA 上的验证。"""
import sys
import urllib.parse

sys.path.insert(0, ".")
from autosqli.core.models import TargetSpec
from autosqli.core.session import HttpSession
from autosqli.core.detector import Detector
from autosqli.core.waf import WafScanner
from autosqli.core.fingerprint import Fingerprinter


def build_spec(url: str, param: str = "id", security: str = "low") -> TargetSpec:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    base = urllib.parse.urlunparse(parsed._replace(query=""))
    return TargetSpec(
        url=base, method="GET", params=params, param=param, base_value="1",
        login_url="http://localhost/login.php",
        login_user="admin", login_pass="password", security=security,
    )


def main():
    spec = build_spec("http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit")
    session = HttpSession(spec, logger=lambda lvl, msg: print(f"[{lvl}] {msg}"))
    assert session.login(), "DVWA 登录失败"

    det = Detector(session)
    inj = det.analyze()
    print("\n=== 注入点 ===")
    print(inj)
    assert inj is not None, "未发现注入点"

    scanner = WafScanner(session, inj, R_base=det.R_base, R_err=det.R_err)
    report = scanner.scan()
    print("\n=== WAF 报告（被过滤项）===")
    for it in report.filtered_list():
        print(f"  {it.token}: {it.evidence}")
    print(f"has_waf={report.has_waf}, 共 {len(report.items)} 项")

    fp = Fingerprinter(session, inj, R_err=det.R_err)
    fingerprint = fp.run(report)
    print("\n=== 指纹 ===")
    for k, v in fingerprint.to_dict().items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
