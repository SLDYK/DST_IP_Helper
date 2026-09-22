# -*- coding: utf-8 -*-
"""命令行入口。

用法：
    python cli.py                  # 完整检测并自动配置
    python cli.py --dry-run        # 只检测，不修改防火墙 / UPnP
    python cli.py --ports 10999    # 手动指定端口
    python cli.py --cleanup        # 撤销本工具添加的规则与映射
"""

from __future__ import annotations

import argparse
import os
import sys


def _bootstrap() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)


def _fix_console_encoding() -> None:
    """中文 Windows 控制台是 GBK，遇到生僻字符会抛 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _bootstrap()
    _fix_console_encoding()

    parser = argparse.ArgumentParser(
        prog="dst-ip-join",
        description="饥荒联机版 IP 联机助手（检测网络环境并自动配置端口映射）",
    )
    parser.add_argument(
        "--ports",
        help="手动指定端口，逗号分隔，例如 10999,10998；留空则自动识别",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只检测，不修改防火墙规则和 UPnP 端口映射",
    )
    parser.add_argument("--cleanup", action="store_true", help="撤销本工具添加的配置")
    parser.add_argument(
        "-y", "--yes", action="store_true", help="跳过撤销前的确认提示"
    )
    parser.add_argument(
        "--list-clusters", action="store_true",
        help="列出本机所有饥荒存档（名称 / 端口 / 模组数）",
    )
    parser.add_argument(
        "--start-server", metavar="集群名",
        help="拉起指定存档的专用服务器（主世界 + 洞穴），按 Ctrl+C 停止",
    )
    parser.add_argument(
        "--update-mods", action="store_true",
        help="启动服务器前先更新模组（默认跳过，启动更快）",
    )
    parser.add_argument(
        "--set-token", metavar="集群名",
        help="把令牌写入该存档的 cluster_token.txt（令牌本身从 --token 传入或标准输入）",
    )
    parser.add_argument("--token", metavar="令牌", help="配合 --set-token 使用；省略则从标准输入读取")
    parser.add_argument("--set-paths", action="store_true",
                        help="配合 --game-dir/--storage-root/--conf-dir 保存路径覆盖设置")
    parser.add_argument("--game-dir", metavar="路径", help="手动指定游戏目录（含 bin64\\）")
    parser.add_argument("--storage-root", metavar="路径", help="手动指定存档根目录")
    parser.add_argument("--conf-dir", metavar="名字", help="手动指定 -conf_dir（默认自动）")
    parser.add_argument("--extra-arg", action="append", default=[],
                        help="附加给 nullrenderer 的参数，可重复，如 --extra-arg=-lan")
    parser.add_argument(
        "--attach", action="store_true",
        help="接管当前正在运行的专用服务器（只监控，不重复启动），按 Ctrl+C 脱离",
    )
    parser.add_argument(
        "--stop-server", action="store_true",
        help="停止当前正在运行的专用服务器（含不是本工具启动的）",
    )
    args = parser.parse_args(argv)

    from dst_ip_join import diagnostics, server

    def log(message: str) -> None:
        print(message, flush=True)

    # ---- 通用化：路径覆盖设置 -------------------------------------------------
    if args.set_paths:
        s = server.Settings(
            game_dir=(args.game_dir or "").strip(),
            storage_root=(args.storage_root or "").strip(),
            conf_dir=(args.conf_dir or "").strip(),
            extra_args=list(args.extra_arg),
        )
        server.set_settings(s)
        server.save_settings(s)
        storage_hint = s.storage_root or "(<文档>\\Klei)"
        print("已保存路径设置：")
        print(f"  游戏目录: {s.game_dir or '(自动探测)'}")
        print(f"  存档根  : {storage_hint}")
        print(f"  conf_dir: {s.conf_dir or '(自动)'}")
        print(f"  额外参数: {' '.join(s.extra_args) or '(无)'}")
        return 0

    # ---- 通用化：写入令牌 -------------------------------------------------------
    if args.set_token:
        ok, token = server.validate_token(args.token or sys.stdin.read())
        if not ok:
            print(f"令牌无效：{token}")
            return 2
        game_dir, ugc_dir = server.default_install()
        content = server.workshop_content_dir(ugc_dir)
        clusters = server.scan_clusters(workshop_content=content, game_dir=game_dir)
        cluster = next((c for c in clusters
                        if c.name == args.set_token or c.cluster_name == args.set_token),
                       None)
        if cluster is None:
            names = "、".join(c.name for c in clusters)
            print(f"找不到存档：{args.set_token}（现有：{names}）")
            return 2
        dest = server.write_token(cluster, token)
        print(f"已写入 {dest}（{len(token)} 字符）")
        return 0

    # ---- 接管：停止运行中的服务器 ----------------------------------------------
    if args.stop_server:
        game_dir, ugc_dir = server.default_install()
        content = server.workshop_content_dir(ugc_dir)
        clusters = server.scan_clusters(workshop_content=content, game_dir=game_dir)
        attached = server.attach_running_procs(clusters)
        if attached is None:
            print("没有发现正在运行的专用服务器")
            return 1
        n = len(attached.shards)
        cname = attached.cluster.name if attached.cluster else "(未知存档)"
        print(f"正在停止 {cname}（{n} 个分片）…")
        attached.stop_all()
        import time as _t
        _t.sleep(2)
        still = [s.proc_info.pid for s in attached.shards if s.alive]
        if still:
            print(f"[FAIL] 仍有进程未退出：{still}")
            return 2
        print("[OK] 已停止")
        return 0

    # ---- 接管：监控运行中的服务器 ----------------------------------------------
    if args.attach:
        game_dir, ugc_dir = server.default_install()
        content = server.workshop_content_dir(ugc_dir)
        clusters = server.scan_clusters(workshop_content=content, game_dir=game_dir)
        attached = server.attach_running_procs(clusters)
        if attached is None:
            print("没有发现正在运行的专用服务器")
            return 1
        cname = attached.cluster.name if attached.cluster else "(未知存档)"
        print(f"已接管运行中的服务器：{cname}（{len(attached.shards)} 个分片）")
        for s in attached.status():
            print(f"  {s['shard']:8} master={s['is_master']!s:5} port={s['port']} pid={s.get('pid')}")
        print("监控中，按 Ctrl+C 脱离（不会停止服务器）")
        try:
            import time as _t
            while True:
                chunk = attached.pump_logs()
                if chunk:
                    for line in chunk.splitlines():
                        print(f"    {line}", flush=True)
                if not attached.any_running():
                    print("[INFO] 所有分片进程已退出")
                    break
                _t.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[INFO] 已脱离（服务器仍在运行）")
        return 0

    # ---- 开服：列出存档 ------------------------------------------------------
    if args.list_clusters:
        game_dir, ugc_dir = server.default_install()
        content = server.workshop_content_dir(ugc_dir)
        clusters = server.scan_clusters(workshop_content=content, game_dir=game_dir)
        if not clusters:
            print("未发现任何存档集群")
            return 1
        print(f"共 {len(clusters)} 个集群：")
        for c in clusters:
            mods = f"{len(c.mods)} 个模组"
            missing = c.missing_mods()
            if missing:
                mods += f"（{len(missing)} 个未下载）"
            token = "有令牌" if c.has_token else "缺令牌"
            ports = "/".join(str(p) for p in c.ports()) or "?"
            print(f"  {c.name:<12} {c.cluster_name}  端口 {ports}  {mods}  {token}")
            for m in c.mods:
                mark = "" if m.installed else "  ✗未下载"
                print(f"      - {m.display_name}{mark}")
        return 0

    # ---- 开服：拉起服务器 ----------------------------------------------------
    if args.start_server:
        game_dir, ugc_dir = server.default_install()
        content = server.workshop_content_dir(ugc_dir)
        clusters = server.scan_clusters(workshop_content=content, game_dir=game_dir)
        cluster = next((c for c in clusters
                        if c.name == args.start_server or c.cluster_name == args.start_server),
                       None)
        if cluster is None:
            names = "、".join(c.name for c in clusters)
            print(f"找不到存档：{args.start_server}（现有：{names}）")
            return 2
        if not cluster.has_token:
            print(f"{cluster.name} 缺少 cluster_token.txt，服务器无法启动")
            return 3

        # 合并：磁盘里的额外参数 + 命令行 --extra-arg
        extra = list(server.settings().extra_args) + list(args.extra_arg)
        manager = server.ServerManager(cluster, update_mods=args.update_mods,
                                       extra_args=extra)

        def note(stage: str, text: str) -> None:
            prefix = {"ready": "[OK]", "fail": "[FAIL]"}.get(stage, "[INFO]")
            log(f"{prefix} {text}")

        try:
            manager.start_all(
                wait_ready=True,
                callback=note,
            )
        except server.ServerError as exc:
            print(f"[FAIL] 启动失败：{exc}")
            return 4

        print()
        print(f"服务器运行中：{cluster.name} · {cluster.cluster_name}  端口 "
              + "/".join(str(p) for p in cluster.ports()))
        print("按 Ctrl+C 停止")
        try:
            while True:
                chunk = manager.pump_logs()
                if chunk:
                    for line in chunk.splitlines():
                        print(f"    {line}", flush=True)
                if not manager.any_running():
                    print("[INFO] 所有分片进程已退出")
                    break
                import time as _t
                _t.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[INFO] 收到停止信号，正在停止…")
        finally:
            manager.stop_all()
        return 0

    # ---- 默认：网络诊断 --------------------------------------------------------

    if args.cleanup:
        if not args.yes:
            answer = input("将删除本工具添加的防火墙规则和 UPnP 映射，继续？[y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("已取消")
                return 0
        diagnostics.cleanup(log=log)
        return 0

    ports: list[int] | None = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.replace("，", ",").split(",") if p.strip()]
        except ValueError:
            print(f"端口格式不对：{args.ports}")
            return 2

    report = diagnostics.run_diagnosis(
        ports=ports,
        log=log,
        configure=not args.dry_run,
    )

    print()
    print(report.share_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
