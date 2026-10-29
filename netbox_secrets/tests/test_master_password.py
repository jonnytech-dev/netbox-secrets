import base64

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from netbox_secrets.constants import CENSOR_MASTER_KEY
from netbox_secrets.models import SessionKey, UserKey
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY
from netbox_secrets.utils import lock_private_key, private_key_matches, unlock_private_key
from netbox_secrets.utils.throttle import clear_master_password_failures
from utilities.testing import APITestCase, TestCase

PASSWORD = 'correct horse battery staple'
FAST_SCRYPT = 2**14

# Keep the plugin's existing settings and add a cheap scrypt cost so tests run quickly
TEST_PLUGINS_CONFIG = {
    **settings.PLUGINS_CONFIG,
    'netbox_secrets': {
        **(settings.PLUGINS_CONFIG.get('netbox_secrets') or {}),
        'master_password_scrypt_n': FAST_SCRYPT,
        'master_password_max_attempts': 3,
    },
}


def other_keypair():
    """A second keypair that does not match PUBLIC_KEY."""
    from Crypto.PublicKey import RSA

    key = RSA.generate(2048)
    return key.export_key().decode(), key.publickey().export_key().decode()


class CryptoHelperTestCase(TestCase):
    def test_lock_unlock_round_trip(self):
        locked = lock_private_key(PRIVATE_KEY, PASSWORD, FAST_SCRYPT)
        self.assertIn('BEGIN ENCRYPTED PRIVATE KEY', locked)
        self.assertNotIn(PRIVATE_KEY.splitlines()[1], locked)
        unlocked = unlock_private_key(locked, PASSWORD)
        self.assertTrue(private_key_matches(unlocked, PUBLIC_KEY))

    def test_wrong_password_returns_none(self):
        locked = lock_private_key(PRIVATE_KEY, PASSWORD, FAST_SCRYPT)
        self.assertIsNone(unlock_private_key(locked, 'wrong password'))
        self.assertIsNone(unlock_private_key(locked, ''))
        self.assertIsNone(unlock_private_key('', PASSWORD))

    def test_lock_rejects_public_key_and_empty_password(self):
        with self.assertRaises(ValueError):
            lock_private_key(PUBLIC_KEY, PASSWORD, FAST_SCRYPT)
        with self.assertRaises(ValueError):
            lock_private_key(PRIVATE_KEY, '', FAST_SCRYPT)

    def test_private_key_matches(self):
        other_private, other_public = other_keypair()
        self.assertTrue(private_key_matches(PRIVATE_KEY, PUBLIC_KEY))
        self.assertFalse(private_key_matches(other_private, PUBLIC_KEY))
        self.assertFalse(private_key_matches(PUBLIC_KEY, PUBLIC_KEY))
        self.assertFalse(private_key_matches('garbage', PUBLIC_KEY))


@override_settings(PLUGINS_CONFIG=TEST_PLUGINS_CONFIG)
class UserKeyMasterPasswordModelTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username='mp-model-user')

    def setUp(self):
        self.userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)

    def test_set_and_unlock(self):
        self.assertFalse(self.userkey.has_master_password())
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        self.userkey.refresh_from_db()
        self.assertTrue(self.userkey.has_master_password())
        unlocked = self.userkey.unlock_private_key(PASSWORD)
        self.assertEqual(self.userkey.get_master_key(unlocked), self.userkey.get_master_key(PRIVATE_KEY))
        self.assertIsNone(self.userkey.unlock_private_key('wrong password'))

    def test_set_rejects_mismatched_private_key(self):
        other_private, _ = other_keypair()
        with self.assertRaises(ValueError):
            self.userkey.set_master_password(other_private, PASSWORD)
        self.assertFalse(self.userkey.has_master_password())

    def test_clear(self):
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        self.userkey.clear_master_password()
        self.userkey.refresh_from_db()
        self.assertFalse(self.userkey.has_master_password())

    def test_changing_public_key_clears_master_password(self):
        # Two active keys so the public key is allowed to change
        second_user = get_user_model().objects.create_user(username='mp-second-user')
        second = UserKey.objects.create(user=second_user, public_key=PUBLIC_KEY)
        second.activate(self.userkey.get_master_key(PRIVATE_KEY))

        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        _, other_public = other_keypair()
        userkey = UserKey.objects.get(pk=self.userkey.pk)
        userkey.public_key = other_public
        userkey.save()
        userkey.refresh_from_db()
        self.assertFalse(userkey.has_master_password())
        self.assertFalse(userkey.is_active())

    def test_set_after_save_on_same_instance_is_kept(self):
        """Saving twice on one instance must not wipe the master password."""
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        self.userkey.save()
        self.userkey.refresh_from_db()
        self.assertTrue(self.userkey.has_master_password())

    def test_change_log_censors_encrypted_private_key(self):
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        self.userkey.snapshot()
        objectchange = self.userkey.to_objectchange('update')
        self.assertEqual(objectchange.postchange_data.get('encrypted_private_key'), CENSOR_MASTER_KEY)
        self.assertNotIn('ENCRYPTED PRIVATE KEY', str(objectchange.postchange_data))
        self.assertNotIn('ENCRYPTED PRIVATE KEY', str(objectchange.prechange_data))


@override_settings(PLUGINS_CONFIG=TEST_PLUGINS_CONFIG)
class MasterPasswordAPITestCase(APITestCase):
    user_permissions = (
        'netbox_secrets.view_userkey',
        'netbox_secrets.add_userkey',
        'netbox_secrets.change_userkey',
        'netbox_secrets.view_sessionkey',
        'netbox_secrets.add_sessionkey',
    )

    def setUp(self):
        super().setUp()
        clear_master_password_failures(self.user)
        self.userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        self.mp_url = reverse('plugins-api:netbox_secrets-api:userkey-master-password')
        self.sk_url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')

    def set_password(self, **proof):
        data = {'master_password': PASSWORD, 'master_password_confirm': PASSWORD, **proof}
        return self.client.post(self.mp_url, data=data, format='json', **self.header)

    def test_status(self):
        response = self.client.get(self.mp_url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(response.data, {'enabled': True, 'has_master_password': False, 'min_length': 12})

    def test_set_with_private_key(self):
        response = self.set_password(private_key=PRIVATE_KEY)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertTrue(response.data['has_master_password'])
        self.assertTrue(UserKey.objects.get(pk=self.userkey.pk).has_master_password())

    def test_set_rejects_wrong_private_key(self):
        other_private, _ = other_keypair()
        response = self.set_password(private_key=other_private)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(UserKey.objects.get(pk=self.userkey.pk).has_master_password())

    def test_set_requires_proof(self):
        response = self.set_password()
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_set_rejects_short_and_mismatched_passwords(self):
        response = self.client.post(
            self.mp_url,
            data={'private_key': PRIVATE_KEY, 'master_password': 'short', 'master_password_confirm': 'short'},
            format='json',
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(
            self.mp_url,
            data={'private_key': PRIVATE_KEY, 'master_password': PASSWORD, 'master_password_confirm': PASSWORD + 'x'},
            format='json',
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_change_with_current_master_password(self):
        self.set_password(private_key=PRIVATE_KEY)
        new_password = 'a completely different passphrase'
        response = self.client.post(
            self.mp_url,
            data={
                'current_master_password': PASSWORD,
                'master_password': new_password,
                'master_password_confirm': new_password,
            },
            format='json',
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)
        userkey = UserKey.objects.get(pk=self.userkey.pk)
        self.assertIsNone(userkey.unlock_private_key(PASSWORD))
        self.assertIsNotNone(userkey.unlock_private_key(new_password))

    def test_remove(self):
        self.set_password(private_key=PRIVATE_KEY)
        response = self.client.delete(
            self.mp_url, data={'current_master_password': PASSWORD}, format='json', **self.header
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertFalse(response.data['has_master_password'])

    def test_remove_requires_proof(self):
        self.set_password(private_key=PRIVATE_KEY)
        response = self.client.delete(self.mp_url, data={}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(UserKey.objects.get(pk=self.userkey.pk).has_master_password())

    def test_session_key_with_master_password_matches_private_key(self):
        self.set_password(private_key=PRIVATE_KEY)
        response = self.client.post(self.sk_url, data={'master_password': PASSWORD}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        session_key = SessionKey.objects.get(userkey=self.userkey)
        master_key = self.userkey.get_master_key(PRIVATE_KEY)
        # The returned session key unlocks the real master key
        returned = base64.b64decode(response.data['session_key'])
        self.assertEqual(session_key.get_master_key(returned), master_key)

    def test_session_key_wrong_master_password(self):
        self.set_password(private_key=PRIVATE_KEY)
        response = self.client.post(
            self.sk_url, data={'master_password': 'wrong password!!'}, format='json', **self.header
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(SessionKey.objects.filter(userkey=self.userkey).exists())

    def test_session_key_master_password_not_set(self):
        response = self.client.post(self.sk_url, data={'master_password': PASSWORD}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_private_key_still_works(self):
        self.set_password(private_key=PRIVATE_KEY)
        response = self.client.post(self.sk_url, data={'private_key': PRIVATE_KEY}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)

    def test_lockout_after_failed_attempts(self):
        self.set_password(private_key=PRIVATE_KEY)
        for _ in range(3):
            response = self.client.post(
                self.sk_url, data={'master_password': 'wrong password!!'}, format='json', **self.header
            )
            self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        # Locked out, even with the right password
        response = self.client.post(self.sk_url, data={'master_password': PASSWORD}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_429_TOO_MANY_REQUESTS)
        # Pasting the private key is not throttled
        response = self.client.post(self.sk_url, data={'private_key': PRIVATE_KEY}, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        # Clearing the counter (lockout expiry) restores access
        clear_master_password_failures(self.user)
        response = self.client.post(self.sk_url, data={'master_password': PASSWORD}, format='json', **self.header)
        self.assertIn(response.status_code, (status.HTTP_200_OK, status.HTTP_201_CREATED))

    def test_encrypted_private_key_never_in_api(self):
        self.set_password(private_key=PRIVATE_KEY)
        url = reverse('plugins-api:netbox_secrets-api:userkey-detail', kwargs={'pk': self.userkey.pk})
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertNotIn('encrypted_private_key', response.data)
        self.assertNotIn('ENCRYPTED PRIVATE KEY', response.content.decode())

    def test_only_acts_on_own_key(self):
        other_user = get_user_model().objects.create_user(username='mp-other-user')
        other_key = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        self.set_password(private_key=PRIVATE_KEY)
        self.assertFalse(UserKey.objects.get(pk=other_key.pk).has_master_password())
        self.assertTrue(UserKey.objects.get(pk=self.userkey.pk).has_master_password())

    def test_disabled(self):
        config = {
            **TEST_PLUGINS_CONFIG,
            'netbox_secrets': {**TEST_PLUGINS_CONFIG['netbox_secrets'], 'master_password_enabled': False},
        }
        with override_settings(PLUGINS_CONFIG=config):
            response = self.set_password(private_key=PRIVATE_KEY)
            self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
            response = self.client.get(self.mp_url, **self.header)
            self.assertFalse(response.data['enabled'])

    def test_activate_with_master_password(self):
        self.set_password(private_key=PRIVATE_KEY)
        other_user = get_user_model().objects.create_user(username='mp-activate-target')
        target = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        self.assertFalse(target.is_active())
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        response = self.client.post(
            url, data={'master_password': PASSWORD, 'user_key_ids': [target.pk]}, format='json', **self.header
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertTrue(UserKey.objects.get(pk=target.pk).is_active())


@override_settings(PLUGINS_CONFIG=TEST_PLUGINS_CONFIG)
class MasterPasswordViewTestCase(TestCase):
    user_permissions = (
        'netbox_secrets.view_userkey',
        'netbox_secrets.add_userkey',
        'netbox_secrets.change_userkey',
    )

    def setUp(self):
        super().setUp()
        clear_master_password_failures(self.user)
        self.userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)

    def test_userkey_page_shows_master_password_panel(self):
        url = reverse('plugins:netbox_secrets:userkey', kwargs={'pk': self.userkey.pk})
        response = self.client.get(url)
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Set Master Password')
        self.assertContains(response, 'id="master_password_modal"')
        # Unlock modal defaults to the private key tab when no master password is set
        self.assertContains(response, 'data-unlock-mode="key"')

    def test_unlock_modal_defaults_to_password_when_set(self):
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        url = reverse('plugins:netbox_secrets:userkey', kwargs={'pk': self.userkey.pk})
        response = self.client.get(url)
        self.assertContains(response, 'data-unlock-mode="password"')
        self.assertContains(response, 'id="user_master_password"')
        self.assertNotContains(response, 'ENCRYPTED PRIVATE KEY')

    def test_activate_multiple_with_master_password(self):
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        targets = []
        for name in ('mp-view-target-1', 'mp-view-target-2'):
            user = get_user_model().objects.create_user(username=name)
            targets.append(UserKey.objects.create(user=user, public_key=PUBLIC_KEY))

        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_activate'),
            data={'master_password': PASSWORD, 'user_keys': [t.pk for t in targets]},
        )
        self.assertHttpStatus(response, 302)
        for target in targets:
            target.refresh_from_db()
            self.assertTrue(target.is_active(), f"{target} was not activated")

    def test_activate_wrong_master_password(self):
        self.userkey.set_master_password(PRIVATE_KEY, PASSWORD)
        user = get_user_model().objects.create_user(username='mp-view-target-3')
        target = UserKey.objects.create(user=user, public_key=PUBLIC_KEY)
        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_activate'),
            data={'master_password': 'wrong password!!', 'user_keys': [target.pk]},
        )
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'Invalid master password')
        target.refresh_from_db()
        self.assertFalse(target.is_active())
