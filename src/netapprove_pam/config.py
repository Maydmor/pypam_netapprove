"""PAM module configuration, loaded from a root-owned TOML file.

Defaults match the Phase 0 decisions doc. The config path is passed as a PAM
argument (``config=/etc/netapprove/config.toml``); all values have safe defaults
so a missing/partial file still yields a working (network) configuration.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from netapprove_core.keystore import DEFAULT_PIN_DIR

DEFAULT_CONFIG_PATH = Path("/etc/netapprove/config.toml")


@dataclass(frozen=True)
class Config:
    relay_url: str = "https://127.0.0.1:8443"
    cert_fingerprint_sha256: str | None = None  # hex, no colons. None = skip pinning (dev only).
    pin_dir: Path = DEFAULT_PIN_DIR
    validity_window_seconds: int = 90
    approval_timeout_seconds: int = 60
    request_timeout_seconds: float = 4.0
    poll_interval_seconds: float = 1.5
    allow_ssh_fallback: bool = False  # Phase 0: console-only fallback.
    # Backend: "network" (Phase 3) or "mock" (Phase 2 return-code testing).
    backend: str = "network"
    mock_mode: str = "approve"  # approve | deny | unavail
    mock_private_key_path: Path | None = None

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        if not path.is_file():
            return cls()

        raw = tomllib.loads(path.read_text())
        return cls._from_mapping(raw)

    @classmethod
    def _from_mapping(cls, raw: dict) -> "Config":
        defaults = cls()
        pin_dir = Path(raw.get("pin_dir", defaults.pin_dir))
        mock_key = raw.get("mock_private_key_path")

        return cls(
            relay_url=raw.get("relay_url", defaults.relay_url),
            cert_fingerprint_sha256=raw.get("cert_fingerprint_sha256", defaults.cert_fingerprint_sha256),
            pin_dir=pin_dir,
            validity_window_seconds=int(raw.get("validity_window_seconds", defaults.validity_window_seconds)),
            approval_timeout_seconds=int(raw.get("approval_timeout_seconds", defaults.approval_timeout_seconds)),
            request_timeout_seconds=float(raw.get("request_timeout_seconds", defaults.request_timeout_seconds)),
            poll_interval_seconds=float(raw.get("poll_interval_seconds", defaults.poll_interval_seconds)),
            allow_ssh_fallback=bool(raw.get("allow_ssh_fallback", defaults.allow_ssh_fallback)),
            backend=raw.get("backend", defaults.backend),
            mock_mode=raw.get("mock_mode", defaults.mock_mode),
            mock_private_key_path=Path(mock_key) if mock_key else None,
        )
