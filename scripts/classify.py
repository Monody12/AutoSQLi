# -*- coding: utf-8 -*-
"""web218–253 批量分类：拉题面 → 提取 waf 特征 → 分族输出战役表。

只读操作（不 boot 容器）。输出「族 → 题号 → 防护特征 → 建议打法」，供
检查点确认推进顺序。用法：
  python scripts/classify.py --cookie-file C:/.../session.txt
"""
import argparse
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from ctfshow_runner import Api, challenges, detail, load_cookie  # noqa: E402

# 特征规则：按 waf 源码/题面关键词分族（顺序即优先级）
FAMILY_RULES = [
    ("os-shell/写文件族", r"into\s+outfile|secure_file|os-shell", "outfile 条件自查 + os-shell 兜底"),
    ("堆叠/多语句族", r"mysqli_multi|stacked|prepare\s|handler", "堆叠 PREPARE 通道"),
    ("二次编码/解码族", r"base64|strrev|decode|decode_", "--encode 预编码器"),
    ("时间盲注族", r"time|benchmark|sleep\s*\(|延迟", "benchmark 校准模式 + --time-sec"),
    ("布尔/延迟盲注族", r"盲注|bool", "布尔/时间通道"),
    ("过滤加固族", r"preg_match|waf\(|过滤|replace", "形态自适应（先看拦什么放什么）"),
    ("sqlmap 使用族", r"sqlmap", "ua/referer 网关 + 常规通道"),
]


def classify_desc(desc: str) -> tuple[str, str]:
    d = desc or ""
    m = re.search(r"function\s+waf\s*\([^)]*\)\s*\{([^}]{0,400})", d, re.S)
    waf_src = m.group(1).replace("\n", " ").strip()[:120] if m else ""
    for name, pat, tactic in FAMILY_RULES:
        if re.search(pat, d, re.I):
            return name, waf_src or tactic
    return ("待人工看题", waf_src or (d.replace("\n", " ")[:100]))


def main():
    ap = argparse.ArgumentParser(description="web218-253 批量分类")
    ap.add_argument("--cookie-file", default=os.environ.get("CTFSHOW_COOKIE_FILE", ""))
    a = ap.parse_args()
    cookie = load_cookie(a.cookie_file)
    api = Api(cookie)
    items = [c for c in challenges(api, "sql注入")
             if (lambda n: n.isdigit() and 218 <= int(n) <= 253)(
                 re.sub(r"\D", "", c["name"] or ""))]
    items.sort(key=lambda c: int(re.sub(r"\D", "", c["name"])))
    rows = []
    for c in items:
        try:
            d = detail(api, c["id"]).get("data") or {}
            desc = d.get("description") or ""
            solved = "Y" if d.get("solved_by_me") else "N"
        except Exception as e:                       # noqa: BLE001
            desc, solved = f"(详情获取失败: {str(e)[:40]})", "?"
        fam, feat = classify_desc(desc)
        rows.append((c["name"], fam, feat, solved))
        print(f"{c['name']:9s} [{solved}] {fam:14s} {feat[:80]}", flush=True)
    print("\n== 分族统计 ==")
    fams = {}
    for name, fam, feat, solved in rows:
        fams.setdefault(fam, []).append(name)
    for fam, names in sorted(fams.items(), key=lambda kv: -len(kv[1])):
        print(f"{fam:16s} {len(names):2d} 题: {', '.join(names[:12])}"
              + (" ..." if len(names) > 12 else ""))
    unsolved = [r[0] for r in rows if r[3] == "N"]
    print(f"\n未解 {len(unsolved)} 题: {', '.join(unsolved[:20])}")


if __name__ == "__main__":
    main()
