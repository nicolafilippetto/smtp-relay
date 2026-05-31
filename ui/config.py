"""UI runtime configuration.

All values are sourced from environment variables. The container entry
point fails fast if anything required is missing (ENCRYPTION_KEY and
SECRET_KEY are validated at first use by their respective modules).
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class UISettings(BaseSettings):
    """Runtime configuration for the FastAPI UI."""

    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    # Branding.
    app_name: str = Field(default="SMTP Relay", alias="APP_NAME")

    # Session / CSRF.
    session_lifetime_hours: int = Field(
        default=8, alias="SESSION_LIFETIME_HOURS", ge=1, le=168
    )

    # UI login ban policy.
    ui_login_ban_threshold: int = Field(
        default=5, alias="UI_LOGIN_BAN_THRESHOLD", ge=1, le=100
    )
    ui_login_ban_duration_min: int = Field(
        default=30, alias="UI_LOGIN_BAN_DURATION_MIN", ge=1, le=10_000
    )

    # DB & archive paths (shared with the relay).
    database_url: str = Field(alias="DATABASE_URL")
    archive_path: str = Field(default="/data/archive", alias="ARCHIVE_PATH")

    # Mark session/CSRF cookies as Secure (HTTPS-only). True for the Docker
    # deployment (TLS via nginx). The native-Windows build serves plain HTTP on
    # the LAN, where Secure cookies would never be sent by the browser (except on
    # localhost), so the launcher sets SMTP_UI_COOKIE_SECURE=0 there.
    cookie_secure: bool = Field(default=True, alias="SMTP_UI_COOKIE_SECURE")

    # Admin reset hook.
    admin_reset: bool = Field(default=False, alias="ADMIN_RESET")
    admin_new_password: str | None = Field(default=None, alias="ADMIN_NEW_PASSWORD")

    @property
    def session_lifetime_seconds(self) -> int:
        return self.session_lifetime_hours * 3600


_settings: UISettings | None = None


def get_settings() -> UISettings:
    global _settings
    if _settings is None:
        _settings = UISettings()  # type: ignore[call-arg]
    return _settings
