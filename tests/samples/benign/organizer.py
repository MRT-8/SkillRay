"""A benign file organizer script — should trigger zero findings."""

import os
import shutil
from pathlib import Path

EXTENSIONS = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"},
    "documents": {".pdf", ".docx", ".txt", ".md"},
    "code": {".py", ".js", ".ts", ".go", ".rs"},
}


def organize(directory: str = ".") -> dict[str, int]:
    """Organize files in directory by extension type."""
    root = Path(directory)
    counts: dict[str, int] = {}

    for file_path in root.iterdir():
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        target_dir = None

        for category, extensions in EXTENSIONS.items():
            if ext in extensions:
                target_dir = root / category
                break

        if target_dir is None:
            target_dir = root / "other"

        target_dir.mkdir(exist_ok=True)
        dest = target_dir / file_path.name

        if not dest.exists():
            shutil.move(str(file_path), str(dest))
            category_name = target_dir.name
            counts[category_name] = counts.get(category_name, 0) + 1

    return counts


if __name__ == "__main__":
    result = organize()
    for category, count in sorted(result.items()):
        print(f"  {category}: {count} files")
