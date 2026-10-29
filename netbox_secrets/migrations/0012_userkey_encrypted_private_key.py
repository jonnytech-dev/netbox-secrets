from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_secrets', '0011_remove_redundant_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='userkey',
            name='encrypted_private_key',
            field=models.TextField(
                blank=True,
                editable=False,
                help_text="Private key encrypted with the user's master password (PKCS#8, scrypt + AES-256-GCM)",
                null=True,
            ),
        ),
    ]
