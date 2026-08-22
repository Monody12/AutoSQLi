"""AutoSQLi 统一入口：无参数启动图形界面，带参数转 CLI。

  AutoSQLi.exe                      # 双击 → GUI
  AutoSQLi.exe -u "URL" --dump      # 命令行模式
"""
import sys


def main():
    argv = sys.argv[1:]
    if not argv:
        from autosqli.gui import run_app
        run_app()
        return 0
    from autosqli.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
