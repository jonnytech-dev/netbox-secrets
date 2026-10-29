"""
Resolve a user's RSA private key from either a pasted key or their master password.
"""

from ..constants import master_password_enabled
from .throttle import clear_master_password_failures, master_password_locked_out, record_master_password_failure

__all__ = [
    'ERR_MASTER_PASSWORD_DISABLED',
    'ERR_MASTER_PASSWORD_INVALID',
    'ERR_MASTER_PASSWORD_LOCKED',
    'ERR_MASTER_PASSWORD_NOT_SET',
    'ERR_UNLOCK_INPUT_MISSING',
    'resolve_private_key',
]

ERR_UNLOCK_INPUT_MISSING = "Provide either your private key or your master password."
ERR_MASTER_PASSWORD_DISABLED = "Master password unlock is disabled."
ERR_MASTER_PASSWORD_NOT_SET = "No master password is set for your user key."
ERR_MASTER_PASSWORD_INVALID = "Invalid master password."
ERR_MASTER_PASSWORD_LOCKED = "Too many failed master password attempts. Try again later."


def resolve_private_key(user, user_key, private_key=None, master_password=None):
    """
    Return the user's private key from a pasted private key or their master password.

    A pasted private key is returned as-is (callers validate it as they do today).
    A master password unlocks the copy stored on the UserKey. Failed attempts are throttled.

    Returns:
        (private_key, error_message). Exactly one is None.
    """
    if private_key:
        return private_key, None

    if not master_password:
        return None, ERR_UNLOCK_INPUT_MISSING
    if not master_password_enabled():
        return None, ERR_MASTER_PASSWORD_DISABLED
    if user_key is None or not user_key.has_master_password():
        return None, ERR_MASTER_PASSWORD_NOT_SET
    if master_password_locked_out(user):
        return None, ERR_MASTER_PASSWORD_LOCKED

    unlocked = user_key.unlock_private_key(master_password)
    if unlocked is None:
        record_master_password_failure(user)
        return None, ERR_MASTER_PASSWORD_INVALID

    clear_master_password_failures(user)
    return unlocked, None
