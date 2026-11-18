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
    # Silent-endpoint watchdog. An endpoint whose agent hasn't checked in for this long
    # is "silent". If Tailscale says the machine is online (or it's the Hub itself), that's
    # an alert: something may have stopped the agent.
    endpoint_silent_seconds: int = Field(default=120, ge=30, le=3600)
    # With no fresh Tailscale presence data we can't tell asleep from stopped, so wait
    # longer before a softer "stopped checking in" alert.
    endpoint_unknown_alert_seconds: int = Field(default=900, ge=60, le=86400)
    # Presence reports older than this are ignored.
    presence_max_age_seconds: int = Field(default=300, ge=60, le=3600)
    # Known-malware fingerprints: download abuse.ch MalwareBazaar's "recent" list daily.
    # Download only; nothing about your machines is sent. Custom hashes: <data>/intel/custom_sha256.txt
    intel_feed_enabled: bool = True
    abusech_auth_key_file: Path = Path("/run/secrets/abusech_auth_key")
    # Per-endpoint tokens: when true, the shared shipper token is refused and every
    # endpoint must use its own token (python -m app.tokens issue <endpoint_id>).
    strict_endpoint_tokens: bool = False
    # The Hub's read-only copy of the shipper folder, for the agent self-check (agentcheck.py).
    agent_release_dir: Path = Path("/app/shipper_release")

    @property
    def abusech_auth_key(self) -> str | None:
        s = _read_secret(self.abusech_auth_key_file)
        return s.get_secret_value() if s else None

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
