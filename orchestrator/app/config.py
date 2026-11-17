"""Settings loaded from env vars, with secrets read from Docker secret files."""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings


def _read_secret(path: str | None) -> SecretStr | None:
    """Return the secret in `path`, or None if the file is missing or empty."""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    value = p.read_text(encoding="utf-8").strip()
    return SecretStr(value) if value else None


class Settings(BaseSettings):
    soc_env: str = "production"
    log_level: str = "INFO"
    tailscale_ip: str = ""

    chroma_host: str = "chromadb"
    chroma_port: int = 8000
    chroma_collection: str = "soc_telemetry"

    gemini_model: str = "gemini-2.5-flash"
    gemini_api_base: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_timeout_seconds: float = 30.0

    # Threat scores (0-100) at or above this pause for FIDO2 approval.
    warden_threat_threshold: int = 85
    warden_approval_timeout_seconds: int = 120
    webauthn_rp_id: str = ""
    webauthn_origin: str = ""
    # "simulated" checks everything in the assertion except the authenticator's
    # signature. It is refused when SOC_ENV=production.
    warden_assertion_mode: Literal["webauthn", "simulated"] = "webauthn"
    # How long a signed execution order stays valid for the enforcer.
    execution_order_ttl_seconds: int = 300
    # Enrolled passkeys + enrollment codes (a Docker volume).
    warden_data_dir: str = "/var/lib/soc"
    warden_rp_name: str = "SOC Warden"
    # Google Password Manager passkeys are "multi-device" (synced across your
    # Google devices). False = only accept device-bound passkeys/security keys.
    warden_allow_synced_passkeys: bool = True
    # Dashboard: passkey sign-in, then a session cookie for this long.
    dashboard_session_hours: float = Field(default=12, gt=0, le=168)

    gemini_api_key_file: str | None = None
    discord_webhook_url_file: str | None = None
    shipper_token_file: str | None = None
    action_signing_secret_file: str | None = None
    execution_signing_key_file: str | None = None

    @field_validator("warden_threat_threshold")
    @classmethod
    def _threshold_range(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("WARDEN_THREAT_THRESHOLD must be 0-100")
        return v

    @property
    def gemini_api_key(self) -> SecretStr | None:
        return _read_secret(self.gemini_api_key_file)

    @property
    def discord_webhook_url(self) -> SecretStr | None:
        return _read_secret(self.discord_webhook_url_file)

    @property
    def shipper_token(self) -> SecretStr | None:
        return _read_secret(self.shipper_token_file)

    @property
    def action_signing_secret(self) -> SecretStr | None:
        return _read_secret(self.action_signing_secret_file)

    @property
    def execution_signing_key(self) -> SecretStr | None:
        return _read_secret(self.execution_signing_key_file)


@lru_cache
def get_settings() -> Settings:
    return Settings()
