"""macOS 运行包的本机固定签名。

运行包从 CI 出来时只有临时签名（ad-hoc），钥匙串按可执行文件的指纹认程序，换一个包就当成新程序，
重新弹授权框。`runtime start` 在启动组件前用一张本机专用的自签名证书把运行包入口签上，签名的
“指定要求”（designated requirement）固定为 `identifier "tunnelminion"` 加这张证书的指纹，换包后
用同一张证书重签，钥匙串里“始终允许”的记录继续有效。

证书只在这台电脑上生成，放在单独的钥匙串文件里（不进登录钥匙串），全程不用 sudo、不改系统信任
设置、不装软件：

- 用 `cryptography` 生成 RSA 密钥和带“代码签名”用途的自签名证书；
- `security create-keychain` 建 `~/.tunnelminion/code-signing/tunnelminion-signing.keychain-db`，
  密码随机生成，存在同目录的 600 权限文件里，每次签名前先用它解锁；
- `security import -T /usr/bin/codesign` 导入证书和私钥，`set-key-partition-list` 允许 codesign
  直接使用私钥，签名时不弹框；
- `codesign --force --sign <证书 SHA-1> --identifier tunnelminion` 签运行包入口。

钥匙串认的是正在运行的进程，也就是入口可执行文件；`_internal` 里的库保持构建时的签名。

入口被重签后内容变了，与运行包清单里的摘要对不上。签名前先在包里写一份签名记录
（`runtime-package-codesign.json`），写明原摘要和签名后的摘要；校验运行包时只有“原摘要等于清单、
现摘要等于记录”的文件才按签名后的内容通过。

签名失败不影响启动：程序照常运行，只是换包后钥匙串仍会把它当成新程序。
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import BaseModel, ConfigDict, Field, ValidationError

CODE_SIGNING_IDENTIFIER = "tunnelminion"
CODE_SIGNATURE_RECORD_FILE = "runtime-package-codesign.json"
CERTIFICATE_NAME = "TunnelMinion Local Code Signing"
# 用系统自带工具的绝对路径：启动时的 PATH 可能被精简过。
SECURITY = "/usr/bin/security"
CODESIGN = "/usr/bin/codesign"
_KEYCHAIN_FILE = "tunnelminion-signing.keychain-db"
_PASSWORD_FILE = "keychain-password"
_IDENTITY_FILE = "identity.json"
_COMMAND_TIMEOUT_SECONDS = 60.0
_CERTIFICATE_YEARS = 20

CommandRunner = Callable[[Sequence[str]], bool]
"""运行一条命令，返回是否成功；不读取输出。"""


def run_command(command: Sequence[str]) -> bool:
    """不经过 shell 运行固定命令；超时或找不到命令都按失败处理。"""
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


class CodeSigningStatus(StrEnum):
    """一次启动前签名的结果。"""

    SIGNED = "signed"
    ALREADY_SIGNED = "already_signed"
    FAILED = "failed"


class CodeSigningResult(BaseModel):
    """写进 `runtime start` 输出的签名摘要，不含路径和密码。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: CodeSigningStatus
    error_code: str | None = None


class SignedFile(BaseModel):
    """一个被本机重签的运行包文件。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    signed_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    signed_size: int = Field(ge=0)


class CodeSignatureRecord(BaseModel):
    """包内签名记录：哪张证书签了哪些文件，签名前后的摘要各是什么。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default="runtime-package-codesign/v1", frozen=True)
    identity_sha1: str = Field(pattern="^[0-9A-F]{40}$")
    files: dict[str, SignedFile]


def load_signature_record(package_root: Path) -> CodeSignatureRecord | None:
    """读包内签名记录；没有或读不懂时返回 None，此时只认清单原摘要。"""
    path = package_root / CODE_SIGNATURE_RECORD_FILE
    if path.is_symlink() or not path.is_file():
        return None
    try:
        record = CodeSignatureRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ValidationError):
        return None
    return record if record.schema_version == "runtime-package-codesign/v1" else None


def accepts_signed_file(
    record: CodeSignatureRecord | None,
    relative: str,
    expected_sha256: object,
    actual_sha256: str,
    actual_size: int,
) -> bool:
    """清单摘要对不上时，判断这是否正是本机重签过的那个文件。"""
    if record is None:
        return False
    signed = record.files.get(relative)
    return (
        signed is not None
        and signed.original_sha256 == expected_sha256
        and signed.signed_sha256 == actual_sha256
        and signed.signed_size == actual_size
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_private(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class LocalSigningIdentity:
    """这台电脑专用的代码签名证书，第一次用时生成，之后一直用同一张。"""

    def __init__(
        self,
        directory: Path,
        *,
        run: CommandRunner = run_command,
        clock: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ) -> None:
        self._directory = directory
        self._run = run
        self._clock = clock

    @property
    def keychain(self) -> Path:
        return self._directory / _KEYCHAIN_FILE

    def ensure(self) -> str | None:
        """返回可用证书的 SHA-1 指纹并解锁它所在的钥匙串；做不到时返回 None。"""
        existing = self._existing()
        if existing is not None:
            sha1, password = existing
            if self._run((SECURITY, "unlock-keychain", "-p", password, str(self.keychain))):
                return sha1
            return None
        return self._create()

    def _existing(self) -> tuple[str, str] | None:
        identity = self._directory / _IDENTITY_FILE
        password = self._directory / _PASSWORD_FILE
        if not (identity.is_file() and password.is_file() and self.keychain.is_file()):
            return None
        try:
            raw = json.loads(identity.read_text(encoding="utf-8"))
            sha1 = cast(Mapping[str, object], raw)["sha1"]
        except (OSError, ValueError, TypeError, KeyError):
            return None
        if not isinstance(sha1, str) or len(sha1) != 40:
            return None
        return sha1, password.read_text(encoding="utf-8").strip()

    def _create(self) -> str | None:
        """生成证书并导入单独的钥匙串文件；中途失败时清掉半成品，下次重来。"""
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._directory, 0o700)
        if self.keychain.exists():
            # 上次没做完：钥匙串文件在，但证书记录没写成。删掉重建，不碰别的钥匙串。
            self._run((SECURITY, "delete-keychain", str(self.keychain)))
            self.keychain.unlink(missing_ok=True)
        password = secrets.token_urlsafe(32)
        transfer = secrets.token_urlsafe(32)
        p12, sha1 = self._certificate(transfer)
        bundle = self._directory / ".identity.p12"
        _write_private(self._directory / _PASSWORD_FILE, password.encode())
        _write_private(bundle, p12)
        keychain = str(self.keychain)
        try:
            steps: tuple[tuple[str, ...], ...] = (
                (SECURITY, "create-keychain", "-p", password, keychain),
                # 不设自动上锁时间；每次签名前仍会先解锁。
                (SECURITY, "set-keychain-settings", keychain),
                (SECURITY, "unlock-keychain", "-p", password, keychain),
                (
                    SECURITY,
                    "import",
                    str(bundle),
                    "-k",
                    keychain,
                    "-f",
                    "pkcs12",
                    "-P",
                    transfer,
                    "-T",
                    CODESIGN,
                ),
                (
                    SECURITY,
                    "set-key-partition-list",
                    "-S",
                    "apple-tool:,apple:,codesign:",
                    "-s",
                    "-k",
                    password,
                    keychain,
                ),
            )
            for step in steps:
                if not self._run(step):
                    return None
        finally:
            bundle.unlink(missing_ok=True)
        _write_private(
            self._directory / _IDENTITY_FILE,
            json.dumps({"sha1": sha1, "name": CERTIFICATE_NAME}).encode(),
        )
        return sha1

    def _certificate(self, transfer_password: str) -> tuple[bytes, str]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERTIFICATE_NAME)])
        now = self._clock()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365 * _CERTIFICATE_YEARS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
            .sign(key, hashes.SHA256())
        )
        # macOS 的 `security import` 只认老式的 3DES/SHA-1 PKCS#12 加密。
        encryption = (
            PrivateFormat.PKCS12.encryption_builder()
            .kdf_rounds(50_000)
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())
            .build(transfer_password.encode())
        )
        bundle = pkcs12.serialize_key_and_certificates(
            CERTIFICATE_NAME.encode(), key, certificate, None, encryption
        )
        return bundle, certificate.fingerprint(hashes.SHA1()).hex().upper()


class PackageCodeSigner:
    """在 `runtime start` 前把运行包入口签成本机固定身份。"""

    def __init__(self, identity: LocalSigningIdentity, *, run: CommandRunner = run_command) -> None:
        self._identity = identity
        self._run = run

    def sign(self, package_root: Path, manifest_path: Path) -> CodeSigningResult:
        try:
            entrypoint, expected = _entrypoint(manifest_path)
            target = package_root / entrypoint
            actual, size = _sha256(target), target.stat().st_size
        except (OSError, ValueError, KeyError, TypeError, StopIteration):
            return CodeSigningResult(status=CodeSigningStatus.FAILED, error_code="manifest_invalid")
        record = load_signature_record(package_root)
        signed_before = accepts_signed_file(record, entrypoint, expected, actual, size)
        if not signed_before and actual != expected:
            # 入口既不是清单里的原文件，也不是本机签过的版本：不去签一个来历不明的文件。
            return CodeSigningResult(
                status=CodeSigningStatus.FAILED, error_code="entrypoint_modified"
            )
        sha1 = self._identity.ensure()
        if sha1 is None:
            return CodeSigningResult(
                status=CodeSigningStatus.FAILED, error_code="signing_identity_unavailable"
            )
        if signed_before and record is not None and record.identity_sha1 == sha1:
            return CodeSigningResult(status=CodeSigningStatus.ALREADY_SIGNED)
        # 原文件，或者用旧证书签过的文件（证书丢了重新生成）：用当前证书签。
        return self._sign(package_root, entrypoint, expected, sha1)

    def _sign(
        self, package_root: Path, entrypoint: str, expected: str, sha1: str
    ) -> CodeSigningResult:
        target = package_root / entrypoint
        temporary = target.with_name(f".{target.name}.codesign")
        try:
            shutil.copy2(target, temporary)
            signed = self._run(
                (
                    CODESIGN,
                    "--force",
                    "--sign",
                    sha1,
                    "--keychain",
                    str(self._identity.keychain),
                    "--identifier",
                    CODE_SIGNING_IDENTIFIER,
                    "--timestamp=none",
                    str(temporary),
                )
            )
            if not signed:
                return CodeSigningResult(
                    status=CodeSigningStatus.FAILED, error_code="codesign_failed"
                )
            record = CodeSignatureRecord(
                identity_sha1=sha1,
                files={
                    entrypoint: SignedFile(
                        original_sha256=expected,
                        signed_sha256=_sha256(temporary),
                        signed_size=temporary.stat().st_size,
                    )
                },
            )
            # 先写记录再换文件：换文件前中断时入口仍是原文件，按清单原摘要照样通过校验。
            _write_private(
                package_root / CODE_SIGNATURE_RECORD_FILE,
                record.model_dump_json(indent=2).encode(),
            )
            # 换成新文件而不是原地改写，正在运行的旧进程继续用旧文件。
            os.replace(temporary, target)
        except OSError:
            return CodeSigningResult(
                status=CodeSigningStatus.FAILED, error_code="package_unwritable"
            )
        finally:
            temporary.unlink(missing_ok=True)
        return CodeSigningResult(status=CodeSigningStatus.SIGNED)


def _entrypoint(manifest_path: Path) -> tuple[str, str]:
    manifest = cast(Mapping[str, object], json.loads(manifest_path.read_text(encoding="utf-8")))
    entrypoint = manifest["entrypoint"]
    files = cast(Sequence[Mapping[str, object]], manifest["files"])
    expected = next(item["sha256"] for item in files if item["path"] == entrypoint)
    if not isinstance(entrypoint, str) or not isinstance(expected, str):
        raise ValueError("运行包入口无效")
    return entrypoint, expected


def default_signing_directory() -> Path:
    """证书、钥匙串文件和它的密码都放在当前用户的 `~/.tunnelminion/code-signing`。"""
    return Path.home() / ".tunnelminion" / "code-signing"
