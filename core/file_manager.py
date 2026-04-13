"""
FileManager — loads source files from the session directory safely.
"""

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("vulnscan.filemanager")

SKIP_EXTENSIONS = {".bak", ".log", ".pyc", ".pyo", ".class", ".o", ".obj"}
MAX_READ_SIZE = 512 * 1024   # 512 KB read cap per file


class FileManager:
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir.resolve()

    def get_files(self, names: Optional[list[str]] = None) -> dict[str, str]:
        """
        Return {filename: content} for files in the session directory.
        If names is provided, only those files are included.
        """
        result = {}
        for path in sorted(self.session_dir.iterdir()):
            # Safety: ensure within session dir
            try:
                resolved = path.resolve()
                resolved.relative_to(self.session_dir)
            except ValueError:
                log.warning(f"Path escape attempt: {path}")
                continue

            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if not path.is_file():
                continue
            if names and path.name not in names:
                continue

            try:
                size = path.stat().st_size
                if size > MAX_READ_SIZE:
                    log.warning(f"Skipping oversized file: {path.name} ({size} bytes)")
                    continue
                content = path.read_text(errors="replace")
                result[path.name] = content
            except Exception as e:
                log.error(f"Could not read {path.name}: {e}")

        return result