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
   identity-bootstrap.rst
   cli-manage-projects-users-and-roles.rst
   cli-keystone-manage-services.rst
   identity-certificates-for-pki.rst
   identity-domain-specific-config.rst
   identity-url-safe-naming.rst
   identity-case-insensitive.rst
   identity-external-authentication.rst
   identity-integrate-with-ldap.rst
   identity-upgrading.rst
   identity-tokens.rst
   identity-token-binding.rst
   identity-fernet-token-faq.rst
   identity-use-trusts.rst
   identity-caching-layer.rst
   identity-security-compliance.rst
   identity-performance.rst
   identity-keystone-usage-and-features.rst
   identity-auth-token-middleware.rst
   identity-service-api-protection.rst
   identity-troubleshoot.rst
   identity-unified-limits.rst
   token-provider.rst
   federated-identity.rst
   identity-credential-encryption.rst
   endpoint-filtering.rst
   health-check-middleware.rst
   oauth1.rst
