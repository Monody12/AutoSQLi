"""CLI 专用打包入口（console 版可执行文件用）。

与 __main__.py（无参开 GUI）不同，本入口始终走命令行模式，
打包为 console=True 的可执行文件以便正常回显输出。
"""
import sys

from autosqli.cli import main

if __name__ == "__main__":
    sys.exit(main())
