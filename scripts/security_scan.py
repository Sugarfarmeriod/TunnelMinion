"""扫描仓库以及显式构建产物中的可重放秘密和私钥。"""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecretPattern:
    """一个高置信秘密格式。"""

    name: str
    expression: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    """不包含匹配正文的秘密扫描结果。"""

    path: Path
    line: int
    pattern: str


PATTERNS = (
    SecretPattern(
        "private-key-pem",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    SecretPattern(
        "wireguard-private-key",
        re.compile(r"(?im)^\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{42}="),
    ),
    SecretPattern("gateway-token", re.compile(r"tmn_[A-Za-z0-9_-]{30,}")),
    SecretPattern(
        "openai-style-key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}"),
    ),
    SecretPattern(
        "bearer-credential",
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{16,}"),
    ),
)

PLACEHOLDER_MARKERS = (
    "test",
    "fake",
    "example",
    "placeholder",
    "must-not-leak",
    "forbidden",
    "should-not-be-here",
    "wrong-token",
    "secret-value",
    "abcdefghijklmnop",
    "with-more-than-32-characters",
)

SKIPPED_PARTS = {".git", ".venv", ".runtime", "__pycache__"}
SKIPPED_SUFFIXES = {".db", ".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif"}


def repository_files(root: Path) -> tuple[Path, ...]:
    """列出 Git 已跟踪和未忽略的未跟踪文件。"""
    completed = subprocess.run(
        ("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=root,
        check=True,
        capture_output=True,
    )
    return tuple(
        root / Path(value.decode("utf-8")) for value in completed.stdout.split(b"\0") if value
    )


def artifact_files(root: Path, artifacts: Iterable[Path]) -> tuple[Path, ...]:
    """枚举显式产物；缺失、逃逸和符号链接都保守失败。"""
    root = root.resolve()
    files: list[Path] = []
    for value in artifacts:
        candidate = value if value.is_absolute() else root / value
        if candidate.is_symlink():
            raise ValueError(f"产物路径不得是符号链接：{value}")
        try:
            candidate = candidate.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"产物路径不存在：{value}") from exc
        if candidate != root and root not in candidate.parents:
            raise ValueError(f"产物路径逃出仓库：{value}")
        candidates = (candidate,) if candidate.is_file() else tuple(candidate.rglob("*"))
        for path in candidates:
            if path.is_symlink():
                raise ValueError(f"产物不得包含符号链接：{path.relative_to(root)}")
            if path.is_file():
                files.append(path)
    return tuple(files)


def scan_files(paths: Iterable[Path], *, allow_placeholders: bool = True) -> tuple[Finding, ...]:
    """扫描文本和含非 UTF-8 字节的产物，不回显匹配正文。"""
    findings: list[Finding] = []
    for path in paths:
        if SKIPPED_PARTS.intersection(path.parts) or path.suffix.lower() in SKIPPED_SUFFIXES:
            continue
        content = path.read_bytes().decode("utf-8", errors="ignore")
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            for pattern in PATTERNS:
                placeholder = allow_placeholders and any(
                    marker in lowered for marker in PLACEHOLDER_MARKERS
                )
                if pattern.expression.search(line) and not placeholder:
                    findings.append(Finding(path, line_number, pattern.name))
    return tuple(findings)


def scan_repository_and_artifacts(root: Path, artifacts: Iterable[Path]) -> tuple[Finding, ...]:
    """合并仓库和产物扫描；产物重复时采用更严格的无占位符豁免策略。"""
    repository = {path.resolve() for path in repository_files(root)}
    artifact = {path.resolve() for path in artifact_files(root, artifacts)}
    findings = list(scan_files(sorted(repository - artifact)))
    findings.extend(scan_files(sorted(artifact), allow_placeholders=False))
    return tuple(findings)


def main(argv: Sequence[str] | None = None) -> int:
    """运行扫描，只输出位置和类型，不回显可能的秘密正文。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--artifact", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        findings = scan_repository_and_artifacts(root, args.artifact)
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError, ValueError) as exc:
        parser.error(str(exc))
    for finding in findings:
        relative = finding.path.relative_to(root)
        print(f"{relative}:{finding.line}: {finding.pattern}")
    if findings:
        print(f"Security scan failed: {len(findings)} suspected secrets; contents hidden.")
        return 1
    print("Security scan passed: no API key, gateway token, Bearer credential, or private key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
