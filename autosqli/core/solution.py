"""解题方法复盘报告：把工具的自动化过程还原为选手可复现的 payload 步骤。

目的：知其然并知其所以然——每一步给出真实发送过的 payload、
判定依据与背后的原理说明。
"""
from __future__ import annotations

from .models import AnalysisReport


def build_solution_report(report: AnalysisReport, result) -> str:
    """生成 Markdown 复盘（供 CLI 打印 / GUI 展示 / 文件导出）。"""
    s = report.session
    inj = report.injection
    fp = report.fingerprint
    waf = report.waf
    lines = ["# AutoSQLi 解题方法复盘", ""]

    # ---- 1. 目标与注入点 ----
    lines += ["## 1. 注入点",
              "",
              f"- 目标：`{report.target.method} {report.target.url}`"]
    if inj is None:
        lines += ["- 结论：未发现注入点", ""]
        return "\n".join(lines)
    lines += [
        f"- 被测参数：`{inj.param}`（{'数字型，无需闭合' if inj.numeric else f'闭合方式 {inj.closure!r}'}）",
        f"- 尾部注释：`{inj.comment!r}`；payload 形态：`{inj.form}`"
        f"（{'常规空格' if inj.form == 'classic' else 'WAF 过滤下实测命中的绕过形态'}）",
        f"- UNION 列数：{inj.column_count}；回显位：{inj.echo_positions or '无'}",
        "",
    ]

    # ---- 2. WAF 与绕过 ----
    filtered = waf.filtered_list()
    lines += ["## 2. WAF 过滤与绕过", ""]
    if filtered:
        lines += ["| 被过滤项 | 判定依据 | 绕过建议 |", "| --- | --- | --- |"]
        for it in filtered[:12]:
            sug = it.suggestion or "—"
            lines.append(f"| `{it.token}` | {it.evidence[:44]} | {sug[:52]} |")
        lines.append(f"\n共 {len(filtered)} 项被过滤，"
                     f"全部清单见分析报告 JSON。实际采用的形态为 `{inj.form}`。")
    else:
        lines.append("未检出过滤（疑似无 WAF），使用常规 payload 形态。")
    lines.append("")

    # ---- 3. 数据库指纹 ----
    # 盲注/严格 WAF 形态下指纹通道（union/报错）可能取不到库信息，
    # 此时以脱库管道实际取回的值为准
    cur_db = fp.current_db or (result.database if result is not None else "")
    cur_user = fp.current_user or (result.user if result is not None else "")
    ver = fp.version or (result.version if result is not None else "")
    lines += ["## 3. 数据库识别", "",
              f"- DBMS：**{fp.dbms} {ver}**；当前库 `{cur_db or '?'}`；"
              f"用户 `{cur_user or '?'}`",
              f"- 可用通道：回显={fp.echo_visible} 报错={fp.error_visible} "
              f"布尔={fp.boolean_oracle} 时间={fp.time_oracle} 堆叠={fp.stacked}",
              ""]

    # ---- 4. 逐步 payload ----
    lines += ["## 4. 关键步骤与真实 Payload", ""]
    if s is not None and getattr(s, "solution_steps", None):
        for i, (title, payload, note) in enumerate(s.solution_steps, 1):
            lines.append(f"**步骤 {i}：{title}**")
            if note:
                lines.append(f"说明：{note}")
            lines.append("```sql")
            lines.append(payload if payload else "(自动构造)")
            lines.append("```")
            lines.append("")
    else:
        lines.append("（无记录）")

    # ---- 5. 结果 ----
    lines += ["## 5. 脱库结果", ""]
    if result is not None:
        d = result.to_dict()
        dbs = d["databases"] or ([d["database"]] if d["database"] else [])
        lines.append(f"- 数据库：{', '.join(dbs[:8]) if dbs else '—'}")
        for tid, rows in list(d.get("rows", {}).items())[:4]:
            n = len(rows)
            preview = ""
            if rows and rows[0]:
                k0 = next(iter(rows[0]))
                preview = f"，首行 {k0}={str(rows[0][k0])[:40]!r}"
            lines.append(f"- `{tid}`：{n} 行{preview}")
    flags = getattr(s, "found_flags", []) if s else []
    if flags:
        lines.append(f"- 🎉 捕获 flag：`{flags[0]}`")
    lines += ["", "---",
              "*本复盘由 AutoSQLi 自动生成，payload 均为实际发送并生效的请求。*"]
    return "\n".join(lines)
