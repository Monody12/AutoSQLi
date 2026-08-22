# AutoSQLi — CTF SQL 注入自动化分析平台

> 面向 CTF 竞赛（Web / SQLi 方向）与安全教学靶场的自动化 SQL 注入分析工具。
> 核心特色：**WAF 过滤感知** —— 先探测过滤清单，再据此自动裁剪与变换 Payload，避免 sqlmap 在 CTF 强 WAF 场景下"构造不出 Payload"的痛点。

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![GUI](https://img.shields.io/badge/GUI-PyQt6-green) ![License](https://img.shields.io/badge/License-GPL--3.0-red) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

> ⚠️ **免责声明**：本工具仅可用于**授权的 CTF 竞赛、自有靶场（如 DVWA、sqli-labs）与安全教学**。禁止用于任何未授权的真实业务系统，使用者的行为与本项目作者无关。

---

## 项目背景

sqlmap 功能强大，但对 CTF 选手并不友好：

| 痛点 | sqlmap 现状 | AutoSQLi 目标 |
| --- | --- | --- |
| WAF 识别 | 不主动探测过滤规则，tamper 靠人工试 | 内置 SQL 字典 fuzz，输出**被过滤关键字/符号清单** |
| Payload 构造 | 通用模板，被过滤即失败 | 根据 WAF 清单**自动跳过不可行构造**，按规则选择绕过方式 |
| 解题方法 | 只有注入技术维度 | 按 CTF 题型组织：万能密码 / 联合 / 堆叠 / 宽字节 / 报错 / 盲注 / 无列名… |
| 交互 | 命令行为主 | PyQt6 图形界面，流程可视化、结果可导出 |

## 功能规划

### 1. 目标与会话管理
- 输入目标 URL（如 `http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit`）
- 支持 GET / POST，自定义参数、Cookie、User-Agent、Referer
- 内置登录会话保持（适配 DVWA 等需登录靶场：admin/password）
- 请求/响应实时预览

### 2. 注入点自动发现
- 参数自动枚举与逐个 fuzz（GET / POST / Cookie / Header）
- 闭合类型探测：`'`、`"`、`')`、`")`、数字型无引号等
- 注释符可用性探测：`#`、`-- `、`/**/`
- 万能密码验证（`or 1=1`、`or((1)like(1))` 等变形）

### 3. WAF 指纹与过滤清单（核心特色）
- 内置 SQL 字典：关键字（`and or union select information_schema sleep substr updatexml load_file`…）、函数、符号（空格、引号、逗号、注释符、括号…）
- 基于响应差异判定：页面内容 / 长度 / HTTP 状态码 / 报错信息变化
- 输出**被过滤项清单**（WAF 报告），并为每一项给出可用绕过建议：

| 过滤项 | 内置绕过策略 |
| --- | --- |
| 空格 | `/**/` 内联注释、括号法 `union(select(1))` |
| 单引号 | 十六进制 `0x666c6167`、宽字节 `%df'` |
| `and` / `or` | `&&` `\|\|`、`like`、异或 `^` |
| `=` | `like`、`regexp`、`between..and..`、`in` |
| 逗号 | `substr(x from 1 for 1)`、`limit 1 offset 1` |
| `select` | 堆叠 `prepare`/`handler`、MySQL8 `table`/`values row()` |
| `information_schema` | 无列名注入（UNION 重命名法）、`sys`/`mysql` 库替代 |
| `sleep` | `benchmark`、`rlike` 重计算、`lock` 类 |

- 字典外置（YAML/JSON），用户可自行扩充

### 4. 注入类型自动识别
- **有回显**：order by 列数探测、回显位定位
- **报错回显**：SQL 错误信息特征检测（`XPATH syntax error`、`Unknown column`…）
- **布尔盲注**：`1=1` / `1=2` 页面差异判定
- **时间盲注**：`sleep()` 响应时间差异判定
- **堆叠可行性**：`;select 1` / `;show tables` 探测

### 5. WAF 感知 Payload 构造器
- 依据过滤清单**自动跳过**被禁构造（如 `union select` 被禁则不再生成联合查询模板）
- 自动选择绕过链：大小写混淆、双写、内联注释、十六进制、等价函数替换（`mid↔substr`、`if↔case when`、`sleep(5*(cond))`）
- MySQL 版本适配：5.5 / 5.7 / 8.0（8.0 的 `table`、`values row()`、`bin_to_uuid()` 报错等）

### 6. 解题方法库（用户可选，附自动推荐）
- **有回显**：万能密码、联合查询注入、报错注入（`updatexml`/`extractvalue`/`floor`/MySQL8 `bin_to_uuid`）、堆叠注入（UNION 回显、RENAME 狸猫换太子、`HANDLER`、`PREPARE`+`CONCAT`/十六进制）、宽字节注入
- **无回显**：布尔盲注、时间盲注、报错型布尔盲注（`exp(710)`、`cot(0)` 溢出）
- **特殊题型**：无列名盲注（UNION 重命名法）、二次注入（分步引导）、约束攻击（版本/模式检测 + 引导）
- 高级字符串截取备选：`right+ascii`、`insert()` 套娃、`trim()` 剥离

### 7. 数据提取流水线（全自动脱库）
- `version()` / `database()` / `user()` → 库名清单 → 表名 → 列名 → 字段数据
- `group_concat` 优先，超长自动回退 `LIMIT M,N` 逐行 / `substr` 分段（规避 1024 字节截断与 32 字符报错限制）
- 结果以数据库树形结构展示（库→表→列→数据表格）

### 8. GUI（PyQt6）
- 目标配置页 → 分析报告页（WAF 清单表格 / 注入点卡片 / 类型判定）
- 解题方法选择页（自动推荐置顶，禁用不可行方法并标注原因）
- 实时日志、payload 预览与单步执行、数据树、报告导出（Markdown / JSON）

## 架构设计

```
AutoSQLi/
├── autosqli/
│   ├── core/            # 核心引擎（不依赖 GUI，可独立 CLI 运行）
│   │   ├── session.py       # HTTP 会话、登录、请求队列与限速
│   │   ├── detector.py      # 注入点发现（闭合/注释符/参数枚举）
│   │   ├── waf.py           # WAF 字典 fuzz 与过滤清单生成
│   │   ├── fingerprint.py   # 注入类型识别、数据库/版本指纹
│   │   ├── builder.py       # WAF 感知 payload 构造器
│   │   └── pipeline.py      # 库→表→列→数据提取流水线
│   ├── techniques/      # 解题方法插件（一方法一模块，统一接口）
│   ├── tampers/         # 绕过变换插件（space2comment、hex 等）
│   ├── dictionaries/    # 外置字典（关键字、表名、列名，YAML）
│   ├── gui/             # PyQt6 界面
│   └── cli.py           # 无 GUI 命令行入口
├── tests/               # 单元测试（请求构造/绕过变换为纯函数，可离线测试）
├── docs/                # 设计文档、payload 手册
├── README.md / LICENSE / requirements.txt
```

- **core 与 GUI 分离**：核心逻辑可被 CLI / 脚本直接复用，便于自动化测试
- **方法插件化**：每种解题方法实现统一接口（`feasible(waf_report)` / `run(session, ctx)`），WAF 清单先经 `feasible` 过滤
- **请求层可 mock**：探测与爆破逻辑不直接持有 socket，方便离线回归

## 开发路线图

- [x] **Phase 1** — core 框架：会话管理、注入点发现、WAF 过滤清单（DVWA Low 验证通过）
- [x] **Phase 2** — 解题引擎：联合查询 / 报错 / 布尔盲注 / 时间盲注 + WAF 感知构造器（DVWA Low/Medium/High 三级验证：四通道脱库、数字型、两步提交、空报错页自适应）
- [x] **Phase 3** — PyQt6 GUI：完整流程可视化、数据树、报告导出
- [ ] **Phase 4** — 高级方法：堆叠（RENAME/HANDLER/PREPARE）交互式执行、宽字节通道化、无列名注入自动化、二次注入引导；MySQL 8.0 适配（TABLE/VALUES ROW/bin_to_uuid）；打包发布（Windows/Linux）

## 快速开始

### 一键启动 / 停止（推荐）

| 平台 | 启动 | 停止 |
| --- | --- | --- |
| Windows | 双击 `start.bat` | 双击 `stop.bat`（或直接关 GUI 窗口） |
| Linux | `./start.sh` | `./stop.sh` |

- 首次运行自动创建虚拟环境并安装依赖，无需手工操作；
- CLI 快捷入口：`autosqli.bat -u "URL" --dump`（Linux 为 `./autosqli.sh ...`），参数见下文 CLI 手册；
- `stop` 只结束 `python -m autosqli` 进程，不影响系统里其他 Python。

### 手动方式

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux: source .venv/bin/activate
pip install -r requirements.txt

# 图形界面
python -m autosqli.gui

# 命令行（本地 DVWA 一键分析 + 全自动脱库）
python -m autosqli.cli -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --dvwa admin:password --dump
```

## CLI 使用手册（推荐）

CLI 是 AutoSQLi 的一等使用方式：脚本化、可复制粘贴、输出可直接进报告。

### 参数总表

| 参数 | 说明 |
| --- | --- |
| `-u URL` | 目标 URL（必填）。查询串中的参数会被自动拆出 |
| `-p, --param` | 被测参数名；留空自动选择第一个非常量参数 |
| `--method GET\|POST` | 请求方式（配 `--data` 时自动 POST） |
| `--data k=v [k=v ...]` | POST 表单字段 |
| `--cookie k=v [k=v ...]` | 附加 Cookie |
| `--dvwa USER:PASS` | DVWA 类靶场自动登录（解析 user_token） |
| `--security low\|medium\|high` | DVWA 安全等级；high 自动配置两步提交（session-input） |
| `--stage-url URL` | 两步提交入口（先写值再触发：二次注入类题型） |
| `--base-value` | 被测参数基线值（默认 `1`） |
| `--delay 秒` | 请求间隔（限速，防封） |
| `--no-waf` | 跳过 WAF 字典扫描（快速模式；剥离型 WAF 下不建议） |
| `--technique KEY` | 指定通道：`union` / `error` / `bool_blind` / `time_blind` / `stacked` / `auto` |
| `--max-rows N` | 每表最大导出行数（默认 20） |
| `--dump` | 分析后自动全自动脱库 |
| `--report PATH` | 分析报告输出为 JSON |
| `--quiet` | 不打印请求日志 |

### 入口自动发现（给主页即可）

`-p` 留空且 URL 不带查询参数时，工具自动进入发现模式：抓取入口页 → 解析全部
表单（GET/POST、字段与默认值）与带参链接 → 逐候选逐参数试探注入 → 命中后续跑
完整分析/脱库流程。日志中可以看到每个候选的试探结果：

```bash
python -m autosqli.cli -u "http://题目主页/" --dump     # 无需 -p / check.php 路径
```

### 输出解读

1. **注入点行**：闭合/注释/列数/回显位；
2. **WAF 清单**：每项标注「可用 / 已过滤 / 未知」+ 判定依据 + 绕过建议；
3. **指纹**：错误回显、联合回显、布尔/时间盲注、堆叠、宽字节、版本/库/用户；
4. **方法清单**：★ 推荐（WAF 感知自动裁剪）→ 选择通道脱库；
5. 任何响应中出现 flag 格式（`flag{}`/`ctfshow{}`/`CTF2{}` 等）会即时以 `[FLAG]` 报告。

### 实战案例（全部为无人工干预的一次命令通关）

| 靶题 | WAF 特征 | 命令 | 结果 |
| --- | --- | --- | --- |
| DVWA low | 无 | `cli -u ".../sqli/?id=1&Submit=Submit" --dvwa admin:password --dump` | 4 通道全开，users 表全量 |
| DVWA medium | POST 数字型 | `cli -u ".../sqli/" --method POST --data id=1 Submit=Submit --dvwa admin:password --security medium --dump` | union 脱库 |
| DVWA high | 两步提交+空报错页 | `cli -u ".../sqli/?id=1" --dvwa admin:password --security high --dump` | union 脱库 |
| ctfshow web6 | 空格+`/**/`被滤、登录框吞错 | `cli -u ".../index.php" --method POST --data username=admin password=1 -p password --dump` | 括号法 union，flag 124 请求 |
| ctfshow web7 | 空格/tab/引号全滤、数字型 | `cli -u ".../index.php" -p id --dump` | hex marker + inline 形态，flag 126 请求 |
| 强网杯 随便注 | select 等七关键字+点号 | `cli -u ".../index.php?inject=1" --technique stacked --dump` | 堆叠 PREPARE+hex，flag 109 请求 |
| 极客 LoveSQL | 无 | `cli -u ".../check.php?username=admin&password=admin" -p password --dump` | union，flag 133 请求 |
| 极客 BabySQL | 关键字 str_replace 剥离 | 同上 | **or 双写自动还原**，跨库 `ctf.Flag` 拿 flag，144 请求 |

### 形态自适应（WAF 感知核心）

工具会实测命中一种 payload 形态（`injection.form`），此后所有构造自动套用：

| form | 适用环境 | 样式 |
| --- | --- | --- |
| classic | 无过滤 | `1' union select ...` |
| inline | 空格被滤、`/**/` 可用 | `1'/**/union/**/select/**/...` |
| tab | 空格被滤、%09 可用 | `1'\tunion\tselect\t...` |
| paren | 空格与 `/**/` 均被滤 | `1'union(select(a),(b))from(t)` |
| orinject | 关键字被 str_replace 剥离 | `1'unorion selorect ...`（剥离后还原 union select） |

## 测试环境

- 本地 DVWA：`http://localhost`（admin / password，安全等级 Low→Impossible 全覆盖）
- 计划补充 sqli-labs（Less-1~75 经典注入场景）

## 技术栈

Python 3.11+ · PyQt6 · requests · GPL-3.0
