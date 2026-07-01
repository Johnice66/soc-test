from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    root: Path = ROOT
    database_path: Path = Path(os.environ.get("SOC_CONSOLE_DB", ROOT / "data/console.db"))
    reports_path: Path = Path(os.environ.get("SOC_CONSOLE_REPORTS", ROOT / "reports"))
    temp_path: Path = Path(os.environ.get("SOC_CONSOLE_TMP", "/tmp/soc-console"))
    session_hours: int = int(os.environ.get("SOC_CONSOLE_SESSION_HOURS", "12"))
    secure_cookie: bool = os.environ.get("SOC_CONSOLE_SECURE_COOKIE", "false").lower() == "true"
    admin_username: str = os.environ.get("SOC_CONSOLE_ADMIN_USERNAME", "admin")
    admin_password: str = os.environ.get("SOC_CONSOLE_ADMIN_PASSWORD", "")

