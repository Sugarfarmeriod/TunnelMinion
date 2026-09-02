"""校验面试展示 fixture 截图、录屏及其发布边界。"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parent / "assets"
MANIFEST_PATH = ROOT / "asset-manifest.json"
EXPECTED_ASSETS = {
    "overview-readonly-fixture.png",
    "operation-awaiting-approval-fixture.png",
    "degraded-fixture-flow.webm",
}


def _asset_path(relative_path: str) -> Path:
    path = (ROOT / relative_path).resolve()
    if ROOT.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"素材路径越界或不存在：{relative_path}")
    return path


def _png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    if header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        raise ValueError(f"PNG 头无效：{path.name}")
    return struct.unpack(">II", header[16:24])


def main() -> None:
    manifest = cast(dict[str, Any], json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))
    if manifest["schema_version"] != 1 or manifest["publication_status"] != "planned":
        raise ValueError("fixture 素材必须保持 schema v1 与 planned")
    if "未执行真实 A/B" not in manifest["display_label"]:
        raise ValueError("素材缺少真实 A/B 禁止声明")
    if manifest["visual_review"]["result"] != "passed":
        raise ValueError("素材尚未完成逐帧视觉复核")

    assets = manifest["assets"]
    paths = {cast(str, item["path"]) for item in assets}
    actual_files = {path.name for path in ROOT.iterdir() if path.name != MANIFEST_PATH.name}
    if paths != EXPECTED_ASSETS or actual_files != EXPECTED_ASSETS:
        raise ValueError("素材集合与 manifest 不一致")

    for asset in assets:
        path = _asset_path(asset["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != asset["sha256"]:
            raise ValueError(f"素材哈希不匹配：{asset['id']}")
        if path.stat().st_size != asset["bytes"]:
            raise ValueError(f"素材大小不匹配：{asset['id']}")
        if asset["kind"] == "screenshot":
            if _png_size(path) != (asset["width"], asset["height"]):
                raise ValueError(f"截图尺寸不匹配：{asset['id']}")
        elif asset["kind"] == "recording":
            if path.read_bytes()[:4] != b"\x1aE\xdf\xa3" or asset["duration_seconds"] <= 0:
                raise ValueError("WebM 录屏格式或时长无效")
        else:
            raise ValueError(f"未知素材类型：{asset['kind']}")
        if "只" not in asset["claim_boundary"]:
            raise ValueError(f"素材缺少窄范围声明：{asset['id']}")

    print(f"展示 fixture 素材验证通过：{len(assets)} 项")


if __name__ == "__main__":
    main()
