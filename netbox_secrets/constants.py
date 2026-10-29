from django.conf import settings
from django.db.models import Q

# Plugin configuration
_plugin_settings = settings.PLUGINS_CONFIG.get("netbox_secrets", {})

# Secrets configuration
SECRET_PLAINTEXT_MAX_LENGTH = 65535
CENSOR_MASTER_KEY = "********"
CENSOR_MASTER_KEY_CHANGED = "***CHANGED***"

# Session configuration
SESSION_COOKIE_NAME = "netbox_secrets_sessionid"


# Build assignable models Q filter from plugin config
def get_assignable_models_filter() -> Q:
    """Construct Q filter for models that can have secrets assigned."""
    q_filter = Q()
    for app_model in _plugin_settings.get("apps", []):
        try:
            app_label, model = app_model.split(".", 1)
            q_filter |= Q(app_label=app_label, model=model)
        except ValueError:
            continue  # Skip malformed entries
    return q_filter


SECRET_ASSIGNABLE_MODELS = get_assignable_models_filter()

# Key generation settings
DEFAULT_KEY_SIZE = 2048
MIN_KEY_SIZE = 2048
MAX_KEY_SIZE = 8192
KEY_SIZE_INCREMENT = 256


def get_public_key_size() -> int:
    """Return the configured minimum RSA public key size."""
    plugin_settings = settings.PLUGINS_CONFIG.get("netbox_secrets") or {}
    return int(plugin_settings.get("public_key_size", DEFAULT_KEY_SIZE))


# Master password settings
DEFAULT_MASTER_PASSWORD_MIN_LENGTH = 12
DEFAULT_MASTER_PASSWORD_MAX_ATTEMPTS = 5
DEFAULT_MASTER_PASSWORD_LOCKOUT_SECONDS = 900
DEFAULT_MASTER_PASSWORD_SCRYPT_N = 2**17  # ~128 MiB, ~0.5s on a modern CPU


def _master_password_setting(name, default):
    plugin_settings = settings.PLUGINS_CONFIG.get("netbox_secrets") or {}
    return plugin_settings.get(name, default)


def master_password_enabled() -> bool:
    """Return True if users may unlock their private key with a master password."""
    return bool(_master_password_setting("master_password_enabled", True))


def get_master_password_min_length() -> int:
    return int(_master_password_setting("master_password_min_length", DEFAULT_MASTER_PASSWORD_MIN_LENGTH))


def get_master_password_max_attempts() -> int:
    return int(_master_password_setting("master_password_max_attempts", DEFAULT_MASTER_PASSWORD_MAX_ATTEMPTS))


def get_master_password_lockout_seconds() -> int:
    return int(_master_password_setting("master_password_lockout_seconds", DEFAULT_MASTER_PASSWORD_LOCKOUT_SECONDS))


def get_master_password_scrypt_n() -> int:
    """scrypt cost (N). Must be a power of two. Only affects newly locked keys."""
    value = int(_master_password_setting("master_password_scrypt_n", DEFAULT_MASTER_PASSWORD_SCRYPT_N))
    if value < 2**14 or value & (value - 1):
        raise ValueError("master_password_scrypt_n must be a power of two and at least 16384.")
    return value
