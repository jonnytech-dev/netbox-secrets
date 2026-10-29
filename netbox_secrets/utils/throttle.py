"""
Failed-attempt throttling for master password unlocks.

Counts failures per user in Django's cache. After too many failures, further master password
attempts are refused until the lockout window expires. Pasting a private key is not throttled.
"""

import logging

from django.core.cache import cache

from ..constants import get_master_password_lockout_seconds, get_master_password_max_attempts

__all__ = [
    'clear_master_password_failures',
    'master_password_locked_out',
    'record_master_password_failure',
]

logger = logging.getLogger('netbox_secrets.master_password')


def _cache_key(user):
    return f'netbox_secrets:master_password_failures:{user.pk}'


def master_password_locked_out(user) -> bool:
    """Return True if the user has too many recent failed master password attempts."""
    return cache.get(_cache_key(user), 0) >= get_master_password_max_attempts()


def record_master_password_failure(user) -> None:
    """Record one failed master password attempt for the user."""
    key = _cache_key(user)
    timeout = get_master_password_lockout_seconds()
    if cache.add(key, 1, timeout):
        failures = 1
    else:
        try:
            failures = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout)
            failures = 1
    logger.warning("Failed master password attempt for user %s (%d)", user.username, failures)
    if failures >= get_master_password_max_attempts():
        logger.warning("Master password unlock locked out for user %s", user.username)


def clear_master_password_failures(user) -> None:
    """Reset the failure counter after a successful unlock."""
    cache.delete(_cache_key(user))
