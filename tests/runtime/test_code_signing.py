"""macOS 运行包本机固定签名：证书生成、换包重签、签名记录与运行包校验。"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from tests.runtime.test_preflight import _package  # pyright: ignore[reportPrivateUsage]

from tunnelminion.runtime import control, verify_runtime_package
from tunnelminion.runtime.code_signing import (
    CERTIFICATE_NAME,
    CODE_SIGNATURE_RECORD_FILE,
    CODE_SIGNING_IDENTIFIER,
    CodeSignatureRecord,
    CodeSigningResult,
    CodeSigningStatus,
    CommandOutcome,
    LocalSigningIdentity,
    PackageCodeSigner,
    SignedFile,
    default_signing_directory,
    load_signature_record,
    run_command,
)

SCHEMA = Path("schemas/runtime-package-manifest-v1.schema.json")
NOW = dt.datetime(2026, 10, 31, tzinfo=dt.UTC)


class FakeSecurity:
    """假装执行 `security` 和 `codesign`：记下命令，codesign 在文件末尾追加签名。"""

    def __init__(self, *, fail: str | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail = fail
        self.certificates: list[x509.Certificate] = []
        # 当前用户的钥匙串搜索列表，和真实输出一样每行一个带引号的路径。
        self.search_list = ["/Users/someone/Library/Keychains/login.keychain-db"]

    def __call__(self, command: Sequence[str]) -> CommandOutcome:
        values = tuple(command)
        self.commands.append(values)
        action = _action(values)
        if action == self.fail:
            # 错误输出里带上整条命令，用来确认失败说明会去掉密码。
            return CommandOutcome(False, "exit 1: " + " ".join(values))
        if action == "list-keychains":
            output = "".join(f'    "{item}"\n' for item in self.search_list)
            return CommandOutcome(True, output=output)
        if action == "list-keychains-set":
            self.search_list = list(values[values.index("-s") + 1 :])
        if action == "create-keychain":
            Path(values[-1]).write_bytes(b"keychain")
        if action == "import":
            bundle = Path(values[2]).read_bytes()
            password = values[values.index("-P") + 1].encode()
            _, certificate, _ = pkcs12.load_key_and_certificates(bundle, password)
            assert certificate is not None
            self.certificates.append(certificate)
        if action == "codesign":
            sha1 = values[values.index("--sign") + 1]
            with Path(values[-1]).open("ab") as stream:
                stream.write(f"signed-by-{sha1}".encode())
        return CommandOutcome(True)

    def actions(self) -> list[str]:
        return [_action(item) for item in self.commands]


def _action(values: tuple[str, ...]) -> str:
    tool = Path(values[0]).name
    if tool != "security":
        return tool
    return "list-keychains-set" if values[1] == "list-keychains" and "-s" in values else values[1]


def identity(tmp_path: Path, run: FakeSecurity) -> LocalSigningIdentity:
    return LocalSigningIdentity(tmp_path / "code-signing", run=run, clock=lambda: NOW)


def test_identity_is_created_once_in_its_own_keychain_and_reused(tmp_path: Path) -> None:
    run = FakeSecurity()
    local = identity(tmp_path, run)
    sha1 = local.ensure()

    assert sha1 is not None and len(sha1) == 40 and sha1 == sha1.upper()
    assert run.actions() == [
        "create-keychain",
        "set-keychain-settings",
        "unlock-keychain",
        "import",
        "set-key-partition-list",
        "list-keychains",
        "list-keychains-set",
    ]
    # 签名钥匙串追加在搜索列表末尾，原有的钥匙串都还在。
    assert run.search_list == [
        "/Users/someone/Library/Keychains/login.keychain-db",
        os.path.realpath(local.keychain),
    ]
    import_command = run.commands[3]
    assert import_command[import_command.index("-T") + 1] == "/usr/bin/codesign"
    # 除了读搜索列表，每条命令都只针对 TunnelMinion 自己的钥匙串文件。
    target = os.path.realpath(local.keychain)
    assert all(
        any(os.path.realpath(value) == target for value in item)
        for item in run.commands
        if _action(item) != "list-keychains"
    )
    directory = tmp_path / "code-signing"
    assert not (directory / ".identity.p12").exists()
    assert json.loads((directory / "identity.json").read_text(encoding="utf-8"))["sha1"] == sha1
    if os.name != "nt":
        assert (directory / "keychain-password").stat().st_mode & 0o077 == 0
        assert directory.stat().st_mode & 0o077 == 0

    # 证书是带“代码签名”用途的自签名证书，指纹就是签名用的 SHA-1。
    [certificate] = run.certificates
    assert certificate.fingerprint(hashes.SHA1()).hex().upper() == sha1
    assert certificate.subject == certificate.issuer
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        CERTIFICATE_NAME
    )
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.CODE_SIGNING]
    assert certificate.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    assert certificate.not_valid_after_utc > NOW + dt.timedelta(days=365 * 19)

    # 第二次只解锁同一个钥匙串、确认它还在搜索列表里，不再生成证书。
    run.commands.clear()
    assert local.ensure() == sha1
    assert run.actions() == ["unlock-keychain", "list-keychains"]


@pytest.mark.parametrize(
    "step", ["create-keychain", "set-keychain-settings", "unlock-keychain", "import"]
)
def test_failed_creation_leaves_no_identity_and_is_retried_cleanly(
    tmp_path: Path, step: str
) -> None:
    run = FakeSecurity(fail=step)
    local = identity(tmp_path, run)
    assert local.ensure() is None
    directory = tmp_path / "code-signing"
    # 失败说明写明是哪一步，命令里的密码都换成了 ***。
    assert local.failure is not None and local.failure.startswith(f"security {step}: exit 1")
    password = (directory / "keychain-password").read_text(encoding="utf-8")
    assert password not in local.failure
    if step != "set-keychain-settings":
        assert "***" in local.failure
    assert not (directory / "identity.json").exists()
    assert not (directory / ".identity.p12").exists()

    run.fail = None
    run.commands.clear()
    sha1 = local.ensure()
    assert sha1 is not None
    if step != "create-keychain":
        # 上次留下的半成品钥匙串先删掉再重建。
        assert run.actions()[0] == "delete-keychain"
        assert run.actions()[1] == "create-keychain"


def test_unreadable_identity_record_is_rebuilt(tmp_path: Path) -> None:
    run = FakeSecurity()
    local = identity(tmp_path, run)
    first = local.ensure()
    record = tmp_path / "code-signing" / "identity.json"
    for broken in ("not json", json.dumps({"sha1": 7}), json.dumps({})):
        record.write_text(broken, encoding="utf-8")
        run.commands.clear()
        replacement = local.ensure()
        assert replacement is not None and replacement != first
        assert run.actions()[0] == "delete-keychain"


@pytest.mark.parametrize("step", ["list-keychains", "list-keychains-set"])
def test_identity_is_unusable_until_its_keychain_is_in_the_search_list(
    tmp_path: Path, step: str
) -> None:
    """codesign 只在搜索列表里找签名身份：列表读不到或改不了时不给出身份，下次再试。"""
    run = FakeSecurity(fail=step)
    local = identity(tmp_path, run)
    assert local.ensure() is None
    assert local.failure is not None and local.failure.startswith("security list-keychains")
    assert run.search_list == ["/Users/someone/Library/Keychains/login.keychain-db"]

    run.fail = None
    run.commands.clear()
    sha1 = local.ensure()
    assert sha1 is not None
    # 证书已经生成过，这次只解锁并补进搜索列表。
    assert run.actions() == ["unlock-keychain", "list-keychains", "list-keychains-set"]
    assert run.search_list[-1] == os.path.realpath(local.keychain)


def test_locked_keychain_that_cannot_be_unlocked_gives_no_identity(tmp_path: Path) -> None:
    run = FakeSecurity()
    local = identity(tmp_path, run)
    assert local.ensure() is not None
    run.fail = "unlock-keychain"
    assert local.ensure() is None


def test_package_entrypoint_is_signed_once_and_still_verifies(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    run = FakeSecurity()
    local = identity(tmp_path, run)
    signer = PackageCodeSigner(local, run=run)

    assert signer.sign(root, manifest) == CodeSigningResult(status=CodeSigningStatus.SIGNED)
    entrypoint = root / "tunnelminion.bin"
    sha1 = local.ensure()
    assert entrypoint.read_bytes() == f"runtimesigned-by-{sha1}".encode()
    codesign = next(item for item in run.commands if item[0] == "/usr/bin/codesign")
    assert codesign[codesign.index("--identifier") + 1] == CODE_SIGNING_IDENTIFIER
    assert "--timestamp=none" in codesign
    assert not any(path.name.endswith(".codesign") for path in root.iterdir())
    record = load_signature_record(root)
    assert record is not None and record.identity_sha1 == sha1
    verify_runtime_package(root, manifest, SCHEMA, ())

    # 同一张证书已经签过：不再调用 codesign。
    run.commands.clear()
    result = signer.sign(root, manifest)
    assert result.status is CodeSigningStatus.ALREADY_SIGNED
    assert "codesign" not in run.actions()


def test_new_certificate_resigns_an_already_signed_entrypoint(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    run = FakeSecurity()
    first = identity(tmp_path / "first", run)
    assert PackageCodeSigner(first, run=run).sign(root, manifest).status is CodeSigningStatus.SIGNED

    second = identity(tmp_path / "second", run)
    result = PackageCodeSigner(second, run=run).sign(root, manifest)
    assert result.status is CodeSigningStatus.SIGNED
    record = load_signature_record(root)
    assert record is not None and record.identity_sha1 == second.ensure()
    verify_runtime_package(root, manifest, SCHEMA, ())


def test_unknown_or_tampered_entrypoint_is_never_signed(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    run = FakeSecurity()
    signer = PackageCodeSigner(identity(tmp_path, run), run=run)
    (root / "tunnelminion.bin").write_bytes(b"tampered")
    result = signer.sign(root, manifest)
    assert result == CodeSigningResult(
        status=CodeSigningStatus.FAILED, error_code="entrypoint_modified"
    )
    assert run.commands == []

    (tmp_path / "other").mkdir()
    root2, manifest2 = _package(tmp_path / "other")
    assert signer.sign(root2, manifest2).status is CodeSigningStatus.SIGNED
    (root2 / "tunnelminion.bin").write_bytes(b"tampered after signing")
    assert signer.sign(root2, manifest2).error_code == "entrypoint_modified"
    with pytest.raises(ValueError, match="校验失败"):
        verify_runtime_package(root2, manifest2, SCHEMA, ())


@pytest.mark.parametrize(
    "manifest_text",
    ["not json", json.dumps({"files": []}), json.dumps({"entrypoint": "x", "files": []})],
)
def test_unreadable_manifest_is_reported(tmp_path: Path, manifest_text: str) -> None:
    root, manifest = _package(tmp_path)
    manifest.write_text(manifest_text, encoding="utf-8")
    run = FakeSecurity()
    result = PackageCodeSigner(identity(tmp_path, run), run=run).sign(root, manifest)
    assert result.error_code == "manifest_invalid"


def test_non_text_manifest_entrypoint_is_reported(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["files"][0]["sha256"] = 7
    manifest.write_text(json.dumps(value), encoding="utf-8")
    run = FakeSecurity()
    result = PackageCodeSigner(identity(tmp_path, run), run=run).sign(root, manifest)
    assert result.error_code == "manifest_invalid"


def test_signing_failures_leave_the_package_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, manifest = _package(tmp_path)
    entrypoint = root / "tunnelminion.bin"

    no_identity = FakeSecurity(fail="create-keychain")
    signer = PackageCodeSigner(identity(tmp_path / "a", no_identity), run=no_identity)
    result = signer.sign(root, manifest)
    assert result.error_code == "signing_identity_unavailable"
    assert signer.failure is not None and signer.failure.startswith("security create-keychain")

    refused = FakeSecurity(fail="codesign")
    signer = PackageCodeSigner(identity(tmp_path / "b", refused), run=refused)
    result = signer.sign(root, manifest)
    assert result.error_code == "codesign_failed"
    assert signer.failure is not None and signer.failure.startswith("codesign: exit 1")
    # 失败说明只留在签名器上，不进 `start` 输出。
    assert "exit" not in result.model_dump_json()
    assert entrypoint.read_bytes() == b"runtime"
    assert load_signature_record(root) is None

    run = FakeSecurity()
    ready = identity(tmp_path / "c", run)
    assert ready.ensure() is not None

    def unwritable(*_: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr("tunnelminion.runtime.code_signing.os.replace", unwritable)
    result = PackageCodeSigner(ready, run=run).sign(root, manifest)
    assert result.error_code == "package_unwritable"
    assert entrypoint.read_bytes() == b"runtime"
    assert sorted(path.name for path in root.iterdir()) == ["tunnelminion.bin"]
    # 记录写不进去时入口还是原文件，按清单原摘要照样通过校验。
    verify_runtime_package(root, manifest, SCHEMA, ())


def test_signature_record_only_vouches_for_the_exact_signed_file(tmp_path: Path) -> None:
    root, manifest = _package(tmp_path)
    entrypoint = root / "tunnelminion.bin"
    entrypoint.write_bytes(b"signed")
    original = json.loads(manifest.read_text(encoding="utf-8"))["files"][0]["sha256"]
    signed = hashlib.sha256(b"signed").hexdigest()

    def write(files: dict[str, SignedFile]) -> None:
        record = CodeSignatureRecord(identity_sha1="A" * 40, files=files)
        (root / CODE_SIGNATURE_RECORD_FILE).write_text(record.model_dump_json(), encoding="utf-8")

    write(
        {
            "tunnelminion.bin": SignedFile(
                original_sha256=original, signed_sha256=signed, signed_size=6
            )
        }
    )
    verify_runtime_package(root, manifest, SCHEMA, ())

    for files in (
        {
            "tunnelminion.bin": SignedFile(
                original_sha256="0" * 64, signed_sha256=signed, signed_size=6
            )
        },
        {
            "tunnelminion.bin": SignedFile(
                original_sha256=original, signed_sha256="0" * 64, signed_size=6
            )
        },
        {
            "tunnelminion.bin": SignedFile(
                original_sha256=original, signed_sha256=signed, signed_size=7
            )
        },
        {"other.bin": SignedFile(original_sha256=original, signed_sha256=signed, signed_size=6)},
    ):
        write(files)
        with pytest.raises(ValueError, match="校验失败"):
            verify_runtime_package(root, manifest, SCHEMA, ())

    for broken in (
        "not json",
        json.dumps({"schema_version": "x", "identity_sha1": "A" * 40, "files": {}}),
    ):
        (root / CODE_SIGNATURE_RECORD_FILE).write_text(broken, encoding="utf-8")
        assert load_signature_record(root) is None
        with pytest.raises(ValueError, match="校验失败"):
            verify_runtime_package(root, manifest, SCHEMA, ())


def test_start_signs_only_frozen_packages_on_macos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Path, Path]] = []

    class Signer(PackageCodeSigner):
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def sign(self, package_root: Path, manifest_path: Path) -> CodeSigningResult:
            calls.append((package_root, manifest_path))
            return CodeSigningResult(status=CodeSigningStatus.SIGNED)

    monkeypatch.setattr(control, "current_program_dir", lambda: tmp_path)
    assert control.sign_running_package(platform_name="win32", frozen=True) is None
    assert control.sign_running_package(platform_name="darwin", frozen=False) is None
    assert control.sign_running_package(platform_name="darwin") is None
    assert calls == []

    result = control.sign_running_package(platform_name="darwin", frozen=True, signer=Signer())
    assert result is not None and result.status is CodeSigningStatus.SIGNED
    monkeypatch.setattr(control, "PackageCodeSigner", Signer)
    assert control.sign_running_package(platform_name="darwin", frozen=True) is not None
    assert calls == [(tmp_path, tmp_path / "runtime-package-manifest.json")] * 2


def test_commands_run_without_a_shell_and_failures_are_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert run_command((sys.executable, "-c", "pass")) == CommandOutcome(True)
    script = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    failed = run_command((sys.executable, "-c", script))
    assert failed == CommandOutcome(False, "exit 3: boom")
    quiet = run_command((sys.executable, "-c", "print('only stdout'); raise SystemExit(4)"))
    assert quiet == CommandOutcome(False, "exit 4: only stdout")
    missing = run_command(("tunnelminion-command-that-does-not-exist",))
    assert missing == CommandOutcome(False, "FileNotFoundError")

    def slow(*_: object, **__: object) -> None:
        raise subprocess.TimeoutExpired("security", 60)

    monkeypatch.setattr("tunnelminion.runtime.code_signing.subprocess.run", slow)
    assert run_command(("security", "unlock-keychain")) == CommandOutcome(False, "timeout")


def test_signing_material_lives_under_the_users_tunnelminion_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_signing_directory() == tmp_path / ".tunnelminion" / "code-signing"


def _probe(*command: str) -> str:
    """跑一条诊断命令，返回退出码和全部输出。"""
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        return f"$ {' '.join(command)}\n  timeout"
    return f"$ {' '.join(command)}\n  exit {done.returncode}: {(done.stdout + done.stderr).strip()}"


def _signing_diagnostics(local: LocalSigningIdentity, sha1: str, sample: Path) -> str:
    """签名失败时收集排查信息：钥匙串搜索列表、可用身份、几种签法各自的报错。"""
    keychain = str(local.keychain)
    scratch = sample.with_name("diagnostic-copy")
    lines = [
        _probe("/usr/bin/security", "list-keychains", "-d", "user"),
        _probe("/usr/bin/security", "find-identity", "-p", "codesigning", keychain),
        _probe("/usr/bin/security", "find-identity", "-v", "-p", "codesigning", keychain),
        _probe("/usr/bin/xcode-select", "-p"),
    ]
    variants = {
        "no-keychain-flag": ("--sign", sha1),
        "by-name": ("--sign", CERTIFICATE_NAME, "--keychain", keychain),
    }
    for label, arguments in variants.items():
        shutil.copy2(sample, scratch)
        probe = _probe("/usr/bin/codesign", "--force", *arguments, str(scratch))
        lines.append(f"[{label}] {probe}")
    if os.environ.get("CI"):
        # 用户级信任这张证书要不要授权框，信任后能不能签。
        pem = sample.with_name("identity.pem")
        exported = subprocess.run(
            ["/usr/bin/security", "find-certificate", "-c", CERTIFICATE_NAME, "-p", keychain],
            capture_output=True,
            text=True,
            check=False,
        )
        pem.write_text(exported.stdout, encoding="utf-8")
        lines.append(
            "[trust] "
            + _probe(
                "/usr/bin/security",
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-p",
                "codeSign",
                "-k",
                keychain,
                str(pem),
            )
        )
        shutil.copy2(sample, scratch)
        lines.append(
            "[after-trust] "
            + _probe(
                "/usr/bin/codesign", "--force", "--sign", sha1, "--keychain", keychain, str(scratch)
            )
        )
    return "\n".join(lines)


@pytest.mark.skipif(sys.platform != "darwin", reason="只有 macOS 有 security 和 codesign")
def test_real_codesign_accepts_the_untrusted_local_certificate(tmp_path: Path) -> None:
    """在 macOS CI 上真跑一遍：不用 sudo、不改信任设置，自签名证书也能签，指定要求固定。"""
    directory = tmp_path / "code-signing"
    local = LocalSigningIdentity(directory)
    try:
        sha1 = local.ensure()
        assert sha1 is not None, local.failure
        assert local.ensure() == sha1, local.failure
        # 证书没被系统信任也能签；前提是签名钥匙串在当前用户的搜索列表里。
        listed = subprocess.run(
            ["/usr/bin/security", "list-keychains", "-d", "user"],
            check=True,
            capture_output=True,
            text=True,
        )
        assert os.path.realpath(local.keychain) in listed.stdout

        root, manifest = _package(tmp_path)
        entrypoint = root / "tunnelminion.bin"
        sample = tmp_path / "sample-binary"
        shutil.copy2(Path(sys.executable).resolve(), sample)

        def install(version: Path) -> None:
            shutil.copy2(version, entrypoint)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            data = entrypoint.read_bytes()
            value["files"][0].update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            manifest.write_text(json.dumps(value), encoding="utf-8")
            (root / CODE_SIGNATURE_RECORD_FILE).unlink(missing_ok=True)

        def requirement() -> str:
            shown = subprocess.run(
                ["/usr/bin/codesign", "--display", "--requirements", "-", str(entrypoint)],
                check=True,
                capture_output=True,
                text=True,
            )
            return shown.stdout + shown.stderr

        install(sample)
        signer = PackageCodeSigner(local)
        result = signer.sign(root, manifest)
        if result.status is not CodeSigningStatus.SIGNED:
            pytest.fail(
                f"{result.error_code}: {signer.failure}\n"
                + _signing_diagnostics(local, sha1, sample)
            )
        verify_runtime_package(root, manifest, SCHEMA, ())
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(entrypoint)], check=True)
        first = requirement()
        assert f'identifier "{CODE_SIGNING_IDENTIFIER}"' in first
        assert sha1.lower() in first.lower()

        # 换一个“新版本”（内容不同的可执行文件）用同一张证书签，指定要求保持不变。
        other = tmp_path / "other-version"
        shutil.copy2(sample, other)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "other", str(other)],
            check=True,
        )
        assert other.read_bytes() != sample.read_bytes()
        install(other)
        result = signer.sign(root, manifest)
        assert result.status is CodeSigningStatus.SIGNED, signer.failure
        assert requirement() == first
    finally:
        subprocess.run(["/usr/bin/security", "delete-keychain", str(local.keychain)], check=False)
