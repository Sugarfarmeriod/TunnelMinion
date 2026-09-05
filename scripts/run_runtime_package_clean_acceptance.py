"""在搬离源码与开发环境后验证 TunnelMinion 运行包候选。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from uuid import uuid4

import psutil
from pydantic import JsonValue

from tunnelminion.runtime.preflight import verify_runtime_package

MANIFEST_VERSION = "runtime-package-manifest/v1"
FORBIDDEN_PROGRAM_DATA = frozenset(
    {
        "gateway.json",
        "managed-node.json",
        "model.json",
        "node-id",
        "runtime.sqlite3",
    }
)
EXPECTED_NATIVE_EXTENSION_COUNT = 5
STARTUP_TIMEOUT_SECONDS = 30.0
INSTALLED_MANIFEST_FILE = "runtime-package-manifest.json"


def file_sha256(path: Path) -> str:
    """流式计算文件 SHA-256。"""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_package_path(root: Path, relative: str) -> Path:
    """解析 manifest 相对路径并拒绝逃逸包根目录。"""
    candidate = (root / Path(relative)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("manifest 路径逃逸运行包") from exc
    return candidate


safe_package_path = _safe_package_path


def _resolve_entrypoint_args(
    package_root: Path,
    entrypoint_args: Sequence[str],
    package_files: set[str],
) -> list[str]:
    """把清单中指向包内文件的参数解析到搬迁后的绝对路径。"""
    return [
        str(_safe_package_path(package_root, argument)) if argument in package_files else argument
        for argument in entrypoint_args
    ]


def load_and_verify_manifest(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
) -> dict[str, JsonValue]:
    """复用产品启动与安装的权威运行包校验，再返回清单。"""
    verify_runtime_package(package_root, manifest_path, schema_path, ())
    return cast(dict[str, JsonValue], json.loads(manifest_path.read_text(encoding="utf-8")))


def sanitized_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """移除会把开发解释器、项目或用户 site-packages 注入候选的环境变量。"""
    values = dict(os.environ if source is None else source)
    for name in tuple(values):
        if name in {"CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"} or name.startswith(
            "UV_"
        ):
            values.pop(name, None)
    values["PYTHONNOUSERSITE"] = "1"
    return values


def isolated_product_environment(
    empty_path: Path, source: Mapping[str, str] | None = None
) -> dict[str, str]:
    """隐藏 Node 与开发环境，并把常见外部 HTTP 客户端导向不可用的本机端口。"""
    empty_path.mkdir(parents=True, exist_ok=True)
    values = sanitized_environment(source)
    values["PATH"] = str(empty_path.resolve())
    values["HTTP_PROXY"] = "http://127.0.0.1:9"
    values["HTTPS_PROXY"] = "http://127.0.0.1:9"
    values["ALL_PROXY"] = "http://127.0.0.1:9"
    values["NO_PROXY"] = "127.0.0.1,localhost"
    return values


def _source_like_entries(files: Sequence[dict[str, JsonValue]]) -> list[str]:
    """列出不应出现在正式冻结包中的源码与仓库元数据。"""
    forbidden_suffixes = (".py", ".ts", ".tsx")
    entries: list[str] = []
    for item in files:
        value = item.get("path")
        if not isinstance(value, str):
            continue
        parts = Path(value).parts
        if any(part in {".git", "src", "frontend"} for part in parts) or value.lower().endswith(
            forbidden_suffixes
        ):
            entries.append(value)
    return sorted(entries)


def _available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast(int, listener.getsockname()[1])


def _private_host_and_port() -> tuple[str, int]:
    """选择本机可绑定的非环回私网 IPv4 与临时端口。"""
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            parsed = ipaddress.ip_address(address.address)
            if not parsed.is_private or parsed.is_loopback or parsed.is_unspecified:
                continue
            with socket.socket() as listener:
                try:
                    listener.bind((address.address, 0))
                except OSError:
                    continue
                return address.address, cast(int, listener.getsockname()[1])
    raise RuntimeError("当前机器没有可绑定的非环回私网 IPv4 地址")


def _read_json(url: str, timeout_seconds: float) -> tuple[int, dict[str, JsonValue]]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout_seconds) as response:
            return response.status, cast(dict[str, JsonValue], json.load(response))
    except urllib.error.HTTPError as exc:
        with exc:
            body = json.loads(exc.read().decode("utf-8"))
        return exc.code, cast(dict[str, JsonValue], body)


def _wait_for_fixture(port: int, timeout_seconds: float) -> dict[str, JsonValue]:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            status, body = _read_json(
                f"http://127.0.0.1:{port}/__runtime_package_fixture__",
                min(1.0, timeout_seconds),
            )
            if status == 200:
                return body
        except OSError as exc:
            last_error = exc
        time.sleep(0.05)
    raise TimeoutError("运行包 fixture 未在预算内就绪") from last_error


def _wait_for_status(url: str, expected: int, timeout_seconds: float) -> int:
    """在总预算内等待真实产品 HTTP 端点返回预期状态。"""
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=min(1.0, timeout_seconds)) as response:
                if response.status == expected:
                    return response.status
        except OSError as exc:
            last_error = exc
        time.sleep(0.05)
    raise TimeoutError("运行包产品端点未在预算内就绪") from last_error


wait_for_status = _wait_for_status


def _runtime_package_evidence(overview: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """只保留总览中可公开复核的运行包摘要。"""
    local = overview.get("local")
    if not isinstance(local, dict):
        raise ValueError("总览缺少 local section")
    package = local.get("package")
    if not isinstance(package, dict):
        raise ValueError("总览缺少 package section")
    return {
        "kind": package.get("kind"),
        "version": package.get("version"),
        "manifest_schema": package.get("manifest_schema"),
    }


def _component_probe(component: str, port: int) -> int:
    path = "/api/resources/health" if component == "local" else "/v1/capabilities"
    status, _body = _read_json(f"http://127.0.0.1:{port}{path}", 2.0)
    return status


def _path_hits(values: Sequence[str], forbidden_paths: Sequence[Path]) -> int:
    normalized = tuple(path.resolve() for path in forbidden_paths)
    hits = 0
    for value in values:
        if not value:
            continue
        candidate = Path(value).resolve()
        if any(candidate == root or root in candidate.parents for root in normalized):
            hits += 1
    return hits


def _is_native_keyring_backend(backend: str) -> bool:
    """判断当前平台是否发现系统原生凭据后端。"""
    prefix = "keyring.backends.Windows." if sys.platform == "win32" else "keyring.backends.macOS."
    return backend.startswith(prefix)


def run_component(
    entrypoint: Path,
    entrypoint_args: Sequence[str],
    component: str,
    data_dir: Path,
    working_dir: Path,
    forbidden_paths: Sequence[Path],
) -> dict[str, JsonValue]:
    """启动一个候选组件，验证真实端点和开发环境隔离后安全停止。"""
    port = _available_port()
    started = time.monotonic()
    process = subprocess.Popen(
        (
            str(entrypoint),
            *entrypoint_args,
            "--component",
            component,
            "--data-dir",
            str(data_dir),
            "--port",
            str(port),
        ),
        cwd=working_dir,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        try:
            fixture = _wait_for_fixture(port, STARTUP_TIMEOUT_SECONDS)
        except TimeoutError:
            exit_code = process.poll()
            return {
                "component": component,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
                "error_code": (
                    "process-exited-before-ready" if exit_code is not None else "startup-timeout"
                ),
                "exit_code": exit_code,
                "passed": False,
            }
        sys_path = cast(list[str], fixture["sys_path"])
        keyring_backend = cast(str, fixture["keyring_backend"])
        native_extensions = cast(list[str], fixture["native_extensions"])
        probe_status = _component_probe(component, port)
        expected_status = 200 if component == "local" else 401
        passed = (
            fixture["component"] == component
            and fixture["pythonpath_present"] is False
            and fixture["user_site_enabled"] is False
            and _is_native_keyring_backend(keyring_backend)
            and len(native_extensions) == EXPECTED_NATIVE_EXTENSION_COUNT
            and _path_hits(sys_path, forbidden_paths) == 0
            and probe_status == expected_status
            and process.poll() is None
        )
        return {
            "component": component,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
            "error_code": None,
            "exit_code": None,
            "forbidden_path_hits": _path_hits(sys_path, forbidden_paths),
            "http_status": probe_status,
            "keyring_backend": keyring_backend,
            "native_extension_count": len(native_extensions),
            "passed": passed,
            "pythonpath_present": fixture["pythonpath_present"],
            "user_site_enabled": fixture["user_site_enabled"],
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            process.wait(timeout=5)


def _run_public_command(
    entrypoint: Path,
    arguments: Sequence[str],
    working_dir: Path,
    environment: Mapping[str, str],
    input_text: str | None = None,
) -> tuple[int, dict[str, JsonValue] | None, str]:
    """执行包内公开命令，只把结构化结果交给验收逻辑。"""
    try:
        completed = subprocess.run(
            (str(entrypoint), *arguments),
            cwd=working_dir,
            env=environment,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, None, ""
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError:
        body = None
    else:
        body = cast(dict[str, JsonValue], raw) if isinstance(raw, dict) else None
    return completed.returncode, body, completed.stdout + completed.stderr


def _runtime_snapshot(
    body: dict[str, JsonValue] | None,
) -> tuple[str | None, dict[str, tuple[str | None, int | None]]]:
    """提取公开 runtime 输出中用于生命周期验收的最小状态。"""
    runtime = body.get("runtime") if body is not None else None
    if not isinstance(runtime, dict):
        return None, {}
    components = runtime.get("components")
    if not isinstance(components, list):
        return cast(str | None, runtime.get("state")), {}
    snapshot: dict[str, tuple[str | None, int | None]] = {}
    for raw in components:
        if not isinstance(raw, dict) or not isinstance(raw.get("component"), str):
            continue
        snapshot[cast(str, raw["component"])] = (
            cast(str | None, raw.get("state")),
            cast(int | None, raw.get("pid")),
        )
    return cast(str | None, runtime.get("state")), snapshot


def run_product_lifecycle(
    entrypoint: Path,
    package_root: Path,
    candidate_id: str,
    data_dir: Path,
    working_dir: Path,
) -> dict[str, JsonValue]:
    """仅经公开 CLI 验收本地/Gateway 生命周期和保留数据的版本管理。"""
    local_port = _available_port()
    gateway_host, gateway_port = _private_host_and_port()
    profile = working_dir.parent / "config" / "runtime-profile.json"
    install_root = working_dir.parent / "install"
    embedded_manifest = package_root / INSTALLED_MANIFEST_FILE
    environment = isolated_product_environment(working_dir / "empty-path")
    token = "tmn_" + uuid4().hex + uuid4().hex[:8]
    transcript: list[str] = []
    steps: dict[str, JsonValue] = {}

    def execute(
        name: str,
        arguments: Sequence[str],
        input_text: str | None = None,
    ) -> tuple[int, dict[str, JsonValue] | None]:
        code, body, output = _run_public_command(
            entrypoint,
            arguments,
            working_dir,
            environment,
            input_text,
        )
        transcript.append(output)
        evidence: dict[str, JsonValue] = {
            "exit_code": code,
            "json_output": body is not None,
        }
        if body is not None:
            for field in ("status", "error_code"):
                if isinstance(body.get(field), str):
                    evidence[field] = body[field]
        steps[name] = evidence
        return code, body

    started = time.monotonic()
    gateway_code, _gateway = execute(
        "gateway-configure",
        (
            "gateway-configure",
            "--data-dir",
            str(data_dir),
            "--bind-host",
            gateway_host,
            "--bind-port",
            str(gateway_port),
            "--peer-node-id",
            "node_" + uuid4().hex,
            "--peer-host",
            gateway_host,
            "--peer-port",
            str(gateway_port),
            "--allowed-tool",
            "get_node_summary",
            "--secret-store",
            "restricted-file",
        ),
        token,
    )
    configure_code, _configured = execute(
        "runtime-configure",
        (
            "runtime",
            "configure",
            "--profile",
            str(profile),
            "--data-dir",
            str(data_dir),
            "--local-port",
            str(local_port),
            "--enable-gateway",
        ),
    )
    start_code, start_body = execute(
        "runtime-start",
        ("runtime", "start", "--profile", str(profile)),
    )
    repeat_code, repeat_body = execute(
        "runtime-start-repeat",
        ("runtime", "start", "--profile", str(profile)),
    )
    status_code, status_body = execute(
        "runtime-status",
        ("runtime", "status", "--profile", str(profile)),
    )

    health_status: int | None = None
    app_status: int | None = None
    gateway_status: int | None = None
    package: dict[str, JsonValue] = {}
    try:
        health_status = _wait_for_status(
            f"http://127.0.0.1:{local_port}/api/resources/health",
            200,
            STARTUP_TIMEOUT_SECONDS,
        )
        app_status = _wait_for_status(
            f"http://127.0.0.1:{local_port}/app/overview",
            200,
            5.0,
        )
        overview_status, overview = _read_json(
            f"http://127.0.0.1:{local_port}/api/resources/overview",
            5.0,
        )
        if overview_status == 200:
            package = _runtime_package_evidence(overview)
        gateway_status, _gateway_body = _read_json(
            f"http://{gateway_host}:{gateway_port}/v1/capabilities",
            5.0,
        )
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError):
        pass
    finally:
        stop_code, stop_body = execute(
            "runtime-stop",
            ("runtime", "stop", "--profile", str(profile)),
        )
        stopped_status_code, stopped_status_body = execute(
            "runtime-status-stopped",
            ("runtime", "status", "--profile", str(profile)),
        )

    stage_code, stage_body = execute(
        "package-stage",
        (
            "runtime-package",
            "stage",
            "--profile",
            str(profile),
            "--install-root",
            str(install_root),
            "--package-root",
            str(package_root),
            "--manifest",
            str(embedded_manifest),
        ),
    )
    activate_code, activate_body = execute(
        "package-activate",
        (
            "runtime-package",
            "activate",
            "--profile",
            str(profile),
            "--install-root",
            str(install_root),
            "--package-id",
            candidate_id,
        ),
    )
    package_status_code, package_status_body = execute(
        "package-status",
        (
            "runtime-package",
            "status",
            "--profile",
            str(profile),
            "--install-root",
            str(install_root),
        ),
    )
    remove_code, remove_body = execute(
        "package-remove",
        (
            "runtime-package",
            "remove",
            "--profile",
            str(profile),
            "--install-root",
            str(install_root),
        ),
    )

    start_state, start_components = _runtime_snapshot(start_body)
    repeat_state, repeat_components = _runtime_snapshot(repeat_body)
    status_state, status_components = _runtime_snapshot(status_body)
    stop_state, stop_components = _runtime_snapshot(stop_body)
    stopped_state, stopped_components = _runtime_snapshot(stopped_status_body)
    expected_components = {"gateway", "local"}
    start_pids = {name: value[1] for name, value in start_components.items()}
    repeat_pids = {name: value[1] for name, value in repeat_components.items()}
    status_pids = {name: value[1] for name, value in status_components.items()}
    running = all(
        state == "running"
        and set(components) == expected_components
        and all(value[0] == "running" for value in components.values())
        for state, components in (
            (start_state, start_components),
            (repeat_state, repeat_components),
            (status_state, status_components),
        )
    )
    stopped = all(
        state == "stopped"
        and set(components) == expected_components
        and all(value[0] == "stopped" for value in components.values())
        for state, components in (
            (stop_state, stop_components),
            (stopped_state, stopped_components),
        )
    )
    idempotent = (
        all(isinstance(pid, int) for pid in start_pids.values())
        and start_pids == repeat_pids == status_pids
    )
    command_codes = (
        gateway_code,
        configure_code,
        start_code,
        repeat_code,
        status_code,
        stop_code,
        stopped_status_code,
        stage_code,
        activate_code,
        package_status_code,
        remove_code,
    )
    data_preserved = data_dir.is_dir()
    secret_store_preserved = (data_dir / "gateway-secrets").is_dir()
    secret_leak_detected = token in "".join(transcript)
    package_flow = (
        stage_body is not None
        and stage_body.get("package_id") == candidate_id
        and activate_body is not None
        and activate_body.get("current_package_id") == candidate_id
        and package_status_body is not None
        and package_status_body.get("current_package_id") == candidate_id
        and remove_body is not None
        and remove_body.get("data_preserved") is True
        and remove_body.get("secret_store_preserved") is True
    )
    node_available = shutil.which("node", path=environment["PATH"]) is not None
    source_environment_present = any(
        name in environment for name in ("CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV")
    )
    passed = (
        all(code == 0 for code in command_codes)
        and running
        and stopped
        and idempotent
        and health_status == 200
        and app_status == 200
        and gateway_status == 401
        and package.get("kind") == "standalone"
        and package.get("manifest_schema") == "runtime-package-manifest/v2"
        and package_flow
        and data_preserved
        and secret_store_preserved
        and not secret_leak_detected
        and not node_available
        and not source_environment_present
    )
    return {
        "component": "public-runtime",
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "health_status": health_status,
        "app_status": app_status,
        "gateway_status": gateway_status,
        "node_available": node_available,
        "source_environment_present": source_environment_present,
        "external_http_proxy_blocked": True,
        "runtime_package": package,
        "public_cli": True,
        "idempotent_start": idempotent,
        "data_preserved": data_preserved,
        "secret_store_preserved": secret_store_preserved,
        "secret_leak_detected": secret_leak_detected,
        "commands": steps,
        "passed": passed,
    }


def run_acceptance(
    package_root: Path,
    manifest_path: Path,
    schema_path: Path,
    forbidden_paths: Sequence[Path],
) -> dict[str, JsonValue]:
    """复制候选后执行 local/Gateway 相同验收并返回脱敏证据。"""
    manifest = load_and_verify_manifest(package_root, manifest_path, schema_path)
    candidate = cast(dict[str, JsonValue], manifest["candidate"])
    files = cast(list[dict[str, JsonValue]], manifest["files"])
    with tempfile.TemporaryDirectory(prefix="tunnelminion-package-clean-") as temporary:
        sandbox = Path(temporary)
        relocated = sandbox / "program"
        shutil.copytree(package_root, relocated)
        is_v2 = manifest["schema_version"] == "runtime-package-manifest/v2"
        entrypoint = _safe_package_path(relocated, cast(str, manifest["entrypoint"]))
        entrypoint_args = _resolve_entrypoint_args(
            relocated,
            cast(list[str], manifest["entrypoint_args"]),
            {cast(str, item["path"]) for item in files},
        )
        work = sandbox / "work"
        work.mkdir()
        if is_v2:
            results = [
                run_product_lifecycle(
                    entrypoint,
                    relocated,
                    cast(str, candidate["id"]),
                    sandbox / "data",
                    work,
                )
            ]
        else:
            results = [
                run_component(
                    entrypoint,
                    entrypoint_args,
                    component,
                    sandbox / f"data-{component}",
                    work,
                    forbidden_paths,
                )
                for component in ("local", "gateway")
            ]
        program_data_entries = sorted(
            path.name for path in relocated.rglob("*") if path.name in FORBIDDEN_PROGRAM_DATA
        )
    source_entries = _source_like_entries(files) if is_v2 else []
    passed = (
        all(result["passed"] is True for result in results)
        and not program_data_entries
        and not source_entries
    )
    return {
        "schema_version": "runtime-package-clean-acceptance/v1",
        "candidate": candidate,
        "manifest_sha256": file_sha256(manifest_path),
        "package_file_count": len(files),
        "package_size_bytes": sum(cast(int, item["size"]) for item in files),
        "components": cast(JsonValue, results),
        "program_data_entries": cast(JsonValue, program_data_entries),
        "source_entries": cast(JsonValue, source_entries),
        "passed": passed,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """解析候选目录并保存可复核 JSON 报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("schemas"),
    )
    parser.add_argument("--forbid-path", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = run_acceptance(
        args.package_root,
        args.manifest,
        args.schema,
        tuple(args.forbid_path),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["passed"] is True or not args.check else 1


if __name__ == "__main__":
    raise SystemExit(main())
