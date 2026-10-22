"""在一台电脑上采集监听端口、进程来历事实和 Docker 容器，输出 JSON，用于筛选规则评测。

可以和 `process_origin.py`、`web_page.py` 一起复制到其他电脑上单独运行，只需要 psutil：

    python collect_service_facts.py > facts.json

输出含本机程序路径，只应保存在本地，不能提交到仓库。
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

import psutil


def _load(name: str) -> Any:
    """仓库里从源码加载；单独复制到其他电脑时，从同一目录加载。"""
    here = Path(__file__).resolve().parent
    for candidate in (
        here / f"{name}.py",
        here.parent / "src" / "tunnelminion" / "platforms" / f"{name}.py",
    ):
        spec = importlib.util.spec_from_file_location(name, candidate)
        if candidate.is_file() and spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
    raise FileNotFoundError(f"找不到 {name}.py")


_origin = _load("process_origin")
_web = _load("web_page")


def _web_pages(listeners: list[dict[str, Any]], facts: dict[str, Any]) -> dict[str, object]:
    """与产品相同的候选范围：TCP、可访问的地址、不是系统程序或桌面应用。"""
    skipped = {"system", "desktop_app"}
    targets: list[tuple[str, int]] = []
    for item in listeners:
        raw = facts.get(str(item["pid"]))
        origin = _origin.classify_origin(_origin.ProcessFacts(**raw)) if raw else None
        key = (str(item["address"]), int(item["port"]))
        if (
            item["protocol"] == "tcp"
            and (origin is None or origin.value not in skipped)
            and _web.probe_host(key[0]) is not None
            and key not in targets
        ):
            targets.append(key)

    def probe(key: tuple[str, int]) -> Any:
        return _web.probe_web_page(*key)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(probe, targets))
    return {
        f"{address}:{port}": (None if page is None else {"title": page.title})
        for (address, port), page in zip(targets, results, strict=True)
    }


def _listeners() -> list[dict[str, object]]:
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return _lsof_listeners()
    values: dict[tuple[str, str, int, int | None], dict[str, object]] = {}
    for item in connections:
        tcp = item.type == 1  # socket.SOCK_STREAM
        if tcp and item.status != psutil.CONN_LISTEN:
            continue
        if not tcp and item.raddr:
            continue
        if not item.laddr:
            continue
        protocol = "tcp" if tcp else "udp"
        key = (protocol, item.laddr.ip, item.laddr.port, item.pid)
        name = None
        if item.pid is not None:
            try:
                name = psutil.Process(item.pid).name()
            except psutil.Error:
                name = None
        values[key] = {
            "protocol": protocol,
            "address": item.laddr.ip,
            "port": item.laddr.port,
            "pid": item.pid,
            "name": name,
        }
    return sorted(values.values(), key=lambda value: (value["port"], value["protocol"]))  # type: ignore[arg-type, return-value]


def _lsof_listeners() -> list[dict[str, object]]:
    lsof = shutil.which("lsof") or "/usr/sbin/lsof"
    completed = subprocess.run(
        (lsof, "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    values: list[dict[str, object]] = []
    for line in completed.stdout.splitlines()[1:]:
        columns = line.split()
        if len(columns) < 9 or "(LISTEN)" not in columns:
            continue
        address, port = columns[-2].rsplit(":", 1)
        values.append(
            {
                "protocol": "tcp",
                "address": "0.0.0.0" if address == "*" else address.strip("[]"),
                "port": int(port),
                "pid": int(columns[1]),
                "name": columns[0].replace("\\x20", " "),
            }
        )
    return values


def _docker() -> list[dict[str, object]]:
    candidates = [
        shutil.which("docker"),
        str(Path.home() / ".orbstack" / "bin" / "docker"),
        "/opt/homebrew/bin/docker",
        "/usr/local/bin/docker",
    ]
    for path in candidates:
        if not path or not Path(path).exists():
            continue
        completed = subprocess.run(
            (path, "ps", "-a", "--no-trunc", "--format", "{{json .}}"),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            return []
        return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    return []


def main() -> None:
    listeners = _listeners()
    facts: dict[str, Any] = {}
    for item in listeners:
        pid = item["pid"]
        if isinstance(pid, int) and str(pid) not in facts:
            value = _origin.read_process_facts(pid)
            facts[str(pid)] = asdict(value) if value is not None else None
    json.dump(
        {
            "platform": _origin.current_platform(),
            "listeners": listeners,
            "facts": facts,
            "web": _web_pages(listeners, facts),
            "docker": _docker(),
        },
        sys.stdout,
        ensure_ascii=False,
        indent=1,
    )


if __name__ == "__main__":
    main()
