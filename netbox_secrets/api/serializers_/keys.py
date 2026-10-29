import base64

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from netbox_secrets.models import *
from users.api.serializers import UserSerializer

__all__ = [
    'ActivateUserKeySerializer',
    'MasterPasswordRemoveSerializer',
    'MasterPasswordSerializer',
    'MasterPasswordStatusSerializer',
    'SessionKeyCreateSerializer',
    'SessionKeySerializer',
    'UserKeySerializer',
]


class UserKeySerializer(NetBoxModelSerializer):
    """
    Serializer for UserKey model.

    Handles serialization of user encryption keys, including public/private key pairs.
    The private key is write-only and never returned in responses.
    """

    user = UserSerializer(nested=True, required=False)
    public_key = serializers.CharField(help_text="RSA public key in PEM format")
    private_key = serializers.CharField(
        write_only=True, required=False, help_text="RSA private key in PEM format (write-only, used for activation)"
    )
    is_active = serializers.BooleanField(
        read_only=True, help_text="Whether this key has been activated with the master key"
    )
    is_filled = serializers.BooleanField(read_only=True, help_text="Whether this key has a public key configured")

    class Meta:
        model = UserKey
        fields = [
            'id',
            'url',
            'display_url',
            'display',
            'user',
            'public_key',
            'private_key',
            'is_active',
            'is_filled',
            'created',
            'last_updated',
            'tags',
            'custom_fields',
        ]
        brief_fields = ('id', 'display', 'url')

    def create(self, validated_data):
        # Ignore private_key (used only for activation workflows)
        validated_data.pop('private_key', None)

        request = self.context.get('request')
        if request and request.user and request.user.is_authenticated:
            validated_data.setdefault('user', request.user)

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Ignore private_key (used only for activation workflows)
        validated_data.pop('private_key', None)
        validated_data.pop('user', None)
        return super().update(instance, validated_data)


class SessionKeySerializer(serializers.ModelSerializer):
    """
    Serializer for SessionKey model.

    Represents temporary session keys used for encrypting/decrypting secrets.
    The actual session key value is only included in responses when explicitly
    provided via context (e.g., after creation).
    """

    userkey = UserKeySerializer(nested=True, read_only=True)
    session_key = serializers.SerializerMethodField(
        read_only=True, help_text="Base64-encoded session key (only returned on creation)"
    )

    class Meta:
        model = SessionKey
        fields = [
            'id',
            'userkey',
            'session_key',
            'created',
        ]
        brief_fields = ('id', 'display', 'url')

    @extend_schema_field(OpenApiTypes.STR)
    def get_session_key(self, obj):
        """Return session key from context if available (e.g., after creation)."""
        context_key = self.context.get('session_key')
        if context_key:
            return context_key
        key = getattr(obj, 'key', None)
        if key:
            return base64.b64encode(key).decode('utf-8')
        return None


class SessionKeyCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating session keys.

    Requires the user's private key to derive the session key.
    Optionally preserves existing session key instead of creating a new one.
    """

    private_key = serializers.CharField(
        write_only=True,
        required=False,
        help_text="User's RSA private key in PEM format (provide this or master_password)",
    )
    master_password = serializers.CharField(
        write_only=True,
        required=False,
        trim_whitespace=False,
        style={'input_type': 'password'},
        help_text="User's master password, which unlocks their stored private key (provide this or private_key)",
    )
    preserve_key = serializers.BooleanField(
        default=False,
        write_only=True,
        required=False,
        help_text="If true, preserve existing session key instead of creating new one",
    )

    class Meta:
        model = SessionKey
        fields = ['private_key', 'master_password', 'preserve_key']


class ActivateUserKeySerializer(serializers.Serializer):
    """Serializer for activating user keys."""

    private_key = serializers.CharField(
        required=False,
        write_only=True,
        help_text="Administrator's RSA private key in PEM format for deriving master key",
        min_length=1,
        trim_whitespace=True,
    )
    master_password = serializers.CharField(
        required=False,
        write_only=True,
        trim_whitespace=False,
        style={'input_type': 'password'},
        help_text="Administrator's master password (alternative to private_key)",
    )
    user_key_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=True,
        help_text="List of UserKey IDs to activate",
        min_length=1,
        max_length=100,
    )

    def validate(self, attrs):
        if not attrs.get('private_key') and not attrs.get('master_password'):
            raise serializers.ValidationError("Provide your private key or your master password.")
        return attrs

    def validate_user_key_ids(self, value):
        """Remove duplicates while preserving order."""
        return list(dict.fromkeys(value))


class MasterPasswordStatusSerializer(serializers.Serializer):
    """Whether the current user has a master password and whether the feature is enabled."""

    enabled = serializers.BooleanField(read_only=True)
    has_master_password = serializers.BooleanField(read_only=True)
    min_length = serializers.IntegerField(read_only=True)


class MasterPasswordSerializer(serializers.Serializer):
    """
    Set or change the current user's master password.

    Prove ownership with either the private key or the current master password.
    """

    private_key = serializers.CharField(
        write_only=True, required=False, help_text="User's RSA private key in PEM format"
    )
    current_master_password = serializers.CharField(
        write_only=True,
        required=False,
        trim_whitespace=False,
        style={'input_type': 'password'},
        help_text="Current master password (alternative to private_key when changing it)",
    )
    master_password = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
        style={'input_type': 'password'},
        help_text="New master password",
    )
    master_password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
        style={'input_type': 'password'},
        help_text="New master password, repeated",
    )

    def validate(self, attrs):
        from netbox_secrets.constants import get_master_password_min_length

        if not attrs.get('private_key') and not attrs.get('current_master_password'):
            raise serializers.ValidationError("Provide your private key or your current master password.")
        if attrs['master_password'] != attrs['master_password_confirm']:
            raise serializers.ValidationError({'master_password_confirm': "Passwords do not match."})
        min_length = get_master_password_min_length()
        if len(attrs['master_password']) < min_length:
            raise serializers.ValidationError(
                {'master_password': f"Master password must be at least {min_length} characters."}
            )
        return attrs


class MasterPasswordRemoveSerializer(serializers.Serializer):
    """Remove the current user's master password. Requires the private key or current master password."""

    private_key = serializers.CharField(write_only=True, required=False)
    current_master_password = serializers.CharField(
        write_only=True, required=False, trim_whitespace=False, style={'input_type': 'password'}
    )

    def validate(self, attrs):
        if not attrs.get('private_key') and not attrs.get('current_master_password'):
            raise serializers.ValidationError("Provide your private key or your current master password.")
        return attrs
