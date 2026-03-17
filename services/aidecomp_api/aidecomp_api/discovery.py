from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .sample_loader import ROOT

EXEC_EXT_SCORES: dict[str, int] = {
    ".exe": 70,
    ".dll": 45,
    ".sys": 38,
    ".ocx": 34,
    ".efi": 30,
}

SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    ".cache",
    ".cargo",
    ".npm",
    ".pnpm-store",
    "AppData",
    "$Recycle.Bin",
    "System Volume Information",
}

PATH_HINT_SCORES: dict[str, int] = {
    "release": 18,
    "debug": 14,
    "build": 12,
    "dist": 10,
    "bin": 10,
    "out": 8,
    "target": 8,
    "x64": 6,
    "win64": 6,
}

MAX_DISCOVERED = 600


@dataclass(slots=True)
class DiscoveredBinary:
    path: str
    name: str
    source_root: str
    size_bytes: int
    modified_at: str
    modified_ts: float
    priority: int
    reasons: list[str]


def _utc_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _default_roots() -> list[Path]:
    roots: list[Path] = [ROOT.resolve()]

    home = Path.home().resolve()
    if home != ROOT.resolve():
        roots.append(home)

    mnt = Path("/mnt")
    if mnt.is_dir():
        # Typical WSL + Windows development locations.
        candidate_windows_roots = [
            Path("/mnt/c/Users"),
            Path("/mnt/d/Users"),
        ]
        for users_dir in candidate_windows_roots:
            if not users_dir.is_dir():
                continue
            for user_dir in users_dir.iterdir():
                if not user_dir.is_dir():
                    continue
                for tail in ("Desktop", "Downloads", "Documents", "source/repos"):
                    candidate = (user_dir / tail).resolve()
                    if candidate.is_dir():
                        roots.append(candidate)

    # Preserve order while deduplicating.
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def _normalize_roots(roots: list[str] | None) -> list[Path]:
    if not roots:
        return _default_roots()
    out: list[Path] = []
    seen: set[str] = set()
    for raw in roots:
        text = raw.strip()
        if not text:
            continue
        root = Path(text).expanduser().resolve()
        key = str(root)
        if key in seen:
            continue
        if not root.exists() or not root.is_dir():
            continue
        seen.add(key)
        out.append(root)
    return out or _default_roots()


def _safe_iterdir(path: Path):
    try:
        yield from path.iterdir()
    except (PermissionError, OSError):
        return


def _within_depth(root: Path, path: Path, max_depth: int) -> bool:
    try:
        depth = len(path.relative_to(root).parts)
    except ValueError:
        return False
    return depth <= max_depth


def _calc_priority(file_path: Path, root: Path, size_bytes: int, modified_ts: float) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    ext = file_path.suffix.lower()
    ext_score = EXEC_EXT_SCORES.get(ext, 0)
    score += ext_score
    if ext_score > 0:
        reasons.append(f"扩展名 {ext} 可执行概率高")

    path_lower = str(file_path).lower()
    for hint, hint_score in PATH_HINT_SCORES.items():
        if hint in path_lower:
            score += hint_score
            reasons.append(f"路径包含 {hint}")
            break

    if str(file_path).startswith(str(ROOT.resolve())):
        score += 20
        reasons.append("位于当前 AI-DecompVis 工作区附近")
    elif str(file_path).startswith("/mnt/"):
        score += 10
        reasons.append("位于 Windows 挂载盘路径")

    age_sec = max(0.0, time.time() - modified_ts)
    if age_sec <= 3 * 86400:
        score += 20
        reasons.append("最近 3 天有修改")
    elif age_sec <= 30 * 86400:
        score += 10
        reasons.append("最近 30 天有修改")

    if 16 * 1024 <= size_bytes <= 200 * 1024 * 1024:
        score += 8
        reasons.append("文件体积处于常见可分析区间")
    elif size_bytes < 1024:
        score -= 8
        reasons.append("文件体积异常偏小")

    if file_path.name.lower().endswith(("setup.exe", "installer.exe")):
        score -= 6
        reasons.append("疑似安装器壳程序")

    # Very large directories can dominate; keep roots comparable.
    try:
        relative_depth = len(file_path.relative_to(root).parts)
    except ValueError:
        relative_depth = 0
    if relative_depth <= 2:
        score += 4
        reasons.append("路径层级较浅，通常更容易定位")

    return max(0, min(100, score)), reasons


def discover_binaries(
    query: str = "",
    roots: list[str] | None = None,
    limit: int = 40,
    max_depth: int = 5,
) -> tuple[list[DiscoveredBinary], list[str], bool]:
    normalized_roots = _normalize_roots(roots)
    scanned_roots = [str(item) for item in normalized_roots]
    query_lower = query.strip().lower()

    candidates: list[DiscoveredBinary] = []
    scanned_count = 0

    for root in normalized_roots:
        queue: deque[Path] = deque([root])
        while queue:
            current = queue.popleft()
            if not _within_depth(root, current, max_depth):
                continue
            for entry in _safe_iterdir(current):
                name = entry.name
                if entry.is_dir():
                    if name in SKIP_DIRS or name.startswith("."):
                        continue
                    queue.append(entry)
                    continue

                if not entry.is_file():
                    continue

                ext = entry.suffix.lower()
                if ext not in EXEC_EXT_SCORES:
                    continue

                scanned_count += 1
                if scanned_count > MAX_DISCOVERED:
                    break

                full_path = str(entry.resolve())
                if query_lower and query_lower not in name.lower() and query_lower not in full_path.lower():
                    continue

                try:
                    stat = entry.stat()
                except (OSError, PermissionError):
                    continue
                score, reasons = _calc_priority(entry, root, stat.st_size, stat.st_mtime)
                candidates.append(
                    DiscoveredBinary(
                        path=full_path,
                        name=name,
                        source_root=str(root),
                        size_bytes=stat.st_size,
                        modified_at=_utc_iso(stat.st_mtime),
                        modified_ts=stat.st_mtime,
                        priority=score,
                        reasons=reasons[:4],
                    )
                )
            if scanned_count > MAX_DISCOVERED:
                break
        if scanned_count > MAX_DISCOVERED:
            break

    candidates.sort(key=lambda item: (item.priority, item.modified_ts, -len(item.path)), reverse=True)
    truncated = len(candidates) > limit
    return candidates[: max(1, min(limit, 200))], scanned_roots, truncated
