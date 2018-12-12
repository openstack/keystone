.. _identity_management:

====================
Administrator Guides
====================

OpenStack Identity, code-named keystone, is the default Identity
management system for OpenStack. After you install Identity, you
configure it through the ``/etc/keystone/keystone.conf``
configuration file and, possibly, a separate logging configuration
file. You initialize data into Identity by using the ``keystone``
command-line client.

.. toctree::
   :maxdepth: 1

   identity-concepts.rst
   bootstrap.rst
   cli-manage-projects-users-and-roles.rst
   cli-keystone-manage-services.rst
   domain-specific-config.rst
   url-safe-naming.rst
   case-insensitive.rst
   integrate-with-ldap.rst
   upgrading.rst
   tokens.rst
   fernet-token-faq.rst
   use-trusts.rst
   caching-layer.rst
   security-compliance.rst
   resource-options.rst
   performance.rst
   keystone-usage-and-features.rst
   auth-token-middleware.rst
   service-api-protection.rst
   troubleshoot.rst
   unified-limits.rst
   token-provider.rst
   credential-encryption.rst
   endpoint-filtering.rst
   health-check-middleware.rst
   oauth1.rst
   service-catalog.rst
   endpoint-policy.rst
   event_notifications.rst
   auth-totp.rst
   external-authentication.rst
   configure_tokenless_x509.rst
   limit-list-size.rst

.. toctree::
   :maxdepth: 2

   federation/federated_identity.rst
