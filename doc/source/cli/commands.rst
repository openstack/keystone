General keystone-manage options:
--------------------------------

* ``--help`` : display verbose help output.

Invoking ``keystone-manage`` by itself will give you some usage information.

Available commands:

* ``bootstrap``: Perform the basic bootstrap process.
* ``credential_migrate``: Encrypt credentials using a new primary key.
* ``credential_rotate``: Rotate Fernet keys for credential encryption.
* ``credential_setup``: Setup a Fernet key repository for credential encryption.
* ``db_sync``: Sync the database.
* ``db_version``: Print the current migration version of the database.
* ``doctor``: Diagnose common problems with keystone deployments.
* ``domain_config_upload``: Upload domain configuration file.
* ``fernet_rotate``: Rotate keys in the Fernet key repository.
* ``fernet_setup``: Setup a Fernet key repository for token encryption.
* ``mapping_populate``: Prepare domain-specific LDAP backend.
* ``mapping_purge``: Purge the identity mapping table.
* ``mapping_engine``: Test your federation mapping rules.
* ``saml_idp_metadata``: Generate identity provider metadata.
* ``token_flush``: Purge expired tokens.
