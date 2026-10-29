from django import template

from ..constants import get_master_password_min_length, master_password_enabled

register = template.Library()


@register.simple_tag(takes_context=True)
def master_password_state(context):
    """
    Return a dict describing the current user's master password state, for the unlock modal.

    Keys: enabled (feature on), has_master_password (user set one), min_length.
    """
    request = context.get('request')
    user = getattr(request, 'user', None)
    has_master_password = False
    if user is not None and user.is_authenticated:
        from ..models import UserKey

        # values_list avoids building a partially-loaded UserKey (its __init__ reads public_key)
        has_master_password = bool(
            UserKey.objects.filter(user=user, encrypted_private_key__isnull=False)
            .exclude(encrypted_private_key='')
            .values_list('pk', flat=True)
            .first()
        )
    return {
        'enabled': master_password_enabled(),
        'has_master_password': has_master_password,
        'min_length': get_master_password_min_length(),
    }
