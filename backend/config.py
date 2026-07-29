"""
config.py
─────────
Central configuration using Pydantic BaseSettings.
Reads from .env automatically, validates all values at startup,
and gives clear error messages for missing or malformed config.
"""

from pathlib import Path
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Slack ──────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = ""
    SLACK_CHANNEL: str = "#pentest-alerts"

    # ── Ollama (local LLM) ─────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"

    # ── Reports ────────────────────────────────────────────
    REPORTS_DIR: Path = BASE_DIR / "reports"

    # ── Server ─────────────────────────────────────────────
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 3000

    # ── username_enum ──────────────────────────────────────
    # Optional global fallback: an email/username KNOWN to exist on the target,
    # used by username_enum's login-form differential check when the per-scan
    # ScanRequest.known_account_email is not supplied. Empty = not set.
    USERNAME_ENUM_KNOWN_ACCOUNT: str = ""

    # ── Rate limiting ──────────────────────────────────────
    ERROR_MODULE_RATE_LIMIT: int = 5
    SCAN_RATE_LIMIT_PER_MINUTE: int = 10   # max scan starts per minute

    # ── Database ───────────────────────────────────────────
    DATABASE_PATH: Path = BASE_DIR / "backend" / "database" / "pentest_agent.db"

    # ── HTTP request defaults ──────────────────────────────
    REQUEST_TIMEOUT: int = 15
    REQUEST_HEADERS: dict = {
        "User-Agent": "Mozilla/5.0 (PentestAgent/1.0; Security Assessment)",
        "Accept": "*/*",
        "Connection": "close",
    }

    # ── Logging ────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_DIR: Path = BASE_DIR / "logs"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024   # 10 MB per file
    LOG_BACKUP_COUNT: int = 5

    # ── Internal constants ─────────────────────────────────
    SEVERITY_LEVELS: list[str] = ["critical", "high", "medium", "low", "info"]

    # ── Katana crawler ─────────────────────────────────────
    KATANA_PATH: str = "katana"          # path to katana binary (must be in PATH)
    KATANA_DEPTH: int = 5                # crawl depth (-d) — deep enough to exhaust routes
    KATANA_TIMEOUT: int = 0              # wall-clock cap in secs; 0 = no limit, run until katana finishes
    KATANA_CONCURRENCY: int = 10         # katana internal concurrency (-c flag)

    # JS-aware crawling. Modern targets are SPAs (React/Vue/Angular): the
    # initial HTML is an almost-empty shell and every real route/endpoint is
    # rendered or referenced from JavaScript. Plain HTML crawling finds 2-3
    # URLs and misses everything. These flags make Katana actually see them.
    KATANA_JS_CRAWL: bool = True         # -jc : parse .js files for endpoints & more JS
    KATANA_HEADLESS: bool = True         # -headless : render SPA routes in real Chrome
    KATANA_KNOWN_FILES: str = "all"      # -kf : also crawl robots.txt + sitemap.xml
    KATANA_RATE_LIMIT: int = 0           # -rl : requests/sec cap (0 = katana default)

    # Post-crawl httpx verification: how many URLs to verify concurrently.
    KATANA_VERIFY_CONCURRENCY: int = 15

    # Scope: keep the exact target host + www. + api.<domain> subdomain.
    # Other subdomains (blog., cdn.) and third-party hosts are always dropped.
    # Turn this off to restrict strictly to the exact host.
    SCOPE_ALLOW_API_SUBDOMAIN: bool = True

    # Scope: also keep ANY subdomain that shares the target's registered domain
    # (e.g. asset.nykaaman.com, static.nykaaman.com when the target is
    # www.nykaaman.com). Modern apps host their JS bundles / assets on a
    # separate same-org subdomain, so without this the crawler can't read them
    # and discovers nothing. Third-party CDNs on a DIFFERENT registered domain
    # (cdn.nykaa.com, images-static.naikaa.com) remain out of scope. Turn off
    # to restrict to the exact host (+ www / api) only.
    SCOPE_ALLOW_SUBDOMAINS: bool = True

    # ── Validators ─────────────────────────────────────────

    @field_validator("BACKEND_PORT", "FRONTEND_PORT", "ERROR_MODULE_RATE_LIMIT",
                     "SCAN_RATE_LIMIT_PER_MINUTE", "REQUEST_TIMEOUT",
                     "KATANA_DEPTH", "KATANA_TIMEOUT", "KATANA_CONCURRENCY",
                     mode="before")
    @classmethod
    def must_be_positive(cls, v: object) -> object:
        try:
            val = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"Must be an integer, got: {v!r}")
        if val <= 0:
            raise ValueError(f"Must be a positive integer, got: {val}")
        return val

    @field_validator("OLLAMA_BASE_URL", mode="before")
    @classmethod
    def validate_ollama_url(cls, v: str) -> str:
        v = str(v).strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"OLLAMA_BASE_URL must start with http:// or https://, got: {v!r}")
        return v

    @field_validator("KATANA_KNOWN_FILES", mode="before")
    @classmethod
    def validate_known_files(cls, v: str) -> str:
        valid = {"all", "robotstxt", "sitemapxml", ""}
        v = str(v).strip().lower()
        if v not in valid:
            raise ValueError(f"KATANA_KNOWN_FILES must be one of {valid}, got: {v!r}")
        return v

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = str(v).upper()
        if v not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {valid}, got: {v!r}")
        return v

    @model_validator(mode="after")
    def ensure_dirs(self) -> "Settings":
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)
        return self

    # ── Helpers ────────────────────────────────────────────

    def slack_configured(self) -> bool:
        """True only if a real Slack webhook URL has been configured."""
        return bool(
            self.SLACK_WEBHOOK_URL
            and not self.SLACK_WEBHOOK_URL.startswith("https://hooks.slack.com/services/YOUR")
        )

    def ollama_url(self) -> str:
        """Full Ollama API endpoint for chat completions."""
        return f"{self.OLLAMA_BASE_URL}/api/chat"


# Single shared instance — import this everywhere
settings = Settings()
