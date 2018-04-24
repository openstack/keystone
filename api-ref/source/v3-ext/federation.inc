.. -*- rst -*-

===================
 OS-FEDERATION API
===================

Provide the ability for users to manage Identity Providers (IdPs) and establish
a set of rules to map federation protocol attributes to Identity API
attributes. Requires v3.0+ of the Identity API.

What's New in Version 1.3
=========================

Corresponding to Identity API v3.5 release.

- Added Identity Provider specific websso routes.


What's New in Version 1.2
=========================

Corresponding to Identity API v3.4 release.

- Add websso routes.


What's New in Version 1.1
=========================

Corresponding to Identity API v3.3 release. These features are considered
stable as of September 4th, 2014.

- Deprecate list projects and domains in favour of core functionality available
  in Identity API v3.3.

- Introduced a mechanism to exchange an Identity Token for a SAML assertion.

- Introduced a mechanism to retrieve Identity Provider Metadata.

Definitions
===========

- *Trusted Identity Provider*: An identity provider set up within the Identity
  API that is trusted to provide authenticated user information.

- *Service Provider*: A system entity that provides services to principals or
  other system entities, in this case, the OpenStack Identity API is the
  Service Provider.

- *Attribute Mapping*: The user information passed by a federation protocol for
  an already authenticated identity are called ``attributes``. Those
  ``attributes`` may not align directly with the Identity API concepts. To help
  overcome such mismatches, a mapping can be done either on the sending side
  (third party identity provider), on the consuming side (Identity API
  service), or both.

- *Protocol*: A protocol capable of performing federated identity authentication.
  For example, the OpenID Connect or SAML 2.0 protocols.

API Resources
=============

Identity Providers
------------------

::

    /v3/OS-FEDERATION/identity_providers

An Identity Provider (IdP) is a third party service that is trusted by the
Identity API to authenticate identities.

Optional attributes:

- ``domain_id`` (string)

  The ID of the domain that is associated with the IdP.

  If a value is not specified by the client, the service will automatically
  create a domain and associate it to the IdP. The ``domain_id`` is not unique
  so that users can link multiple IdPs to one domain.

- ``description`` (string)

  Describes the identity provider.

  If a value is not specified by the client, the service will default this
  value to ``null``.

- ``enabled`` (boolean)

  Indicates whether this identity provider should accept federated
  authentication requests.

  If a value is not specified by the client, the service will default this to
  ``false``.

- ``remote_ids`` (list)

  Valid remote IdP entity values from Identity Providers. If a value is not
  specified by the client, the list will be empty.

Protocols
---------

::

    /v3/OS-FEDERATION/identity_providers/{idp_id}/protocols

A protocol entry contains information that dictates which mapping rules to use
for a given incoming request. An IdP may have multiple supported protocols.

Required attributes:

- ``mapping_id`` (string)

  Indicates which mapping should be used to process federated authentication
  requests.

Mappings
--------

::

    /v3/OS-FEDERATION/mappings

A ``mapping`` is a set of rules to map federation protocol attributes to
Identity API objects. An Identity Provider can have a single ``mapping``
specified per protocol. A mapping is simply a list of ``rules``.

Required attributes:

- ``rules`` (list of objects)

  Each object contains a rule for mapping attributes to Identity API concepts.
  A rule contains a ``remote`` attribute description and the destination
  ``local`` attribute.

- ``local`` (list of objects)

   References a local Identity API resource, such as a ``group`` or ``user`` to
   which the remote attributes will be mapped.

   Each object has one of two structures, as follows.

   To map a remote attribute value directly to a local attribute, identify the
   local resource type and attribute:

   ::

       [
           {
               "local": [
                   {
                       "user": {
                           "name": "{0}"
                       }
                   }
               ],
            }
        ]

   If the ``user`` attribute is missing when processing an assertion, server
   tries to directly map ``REMOTE_USER`` environment variable. If this variable
   is also unavailable the server returns an HTTP ``401 Unauthorized`` error.

   If the ``user`` has the attribute ``type`` set to ``local`` as well as a
   domain specified, the user is treated as existing in the local keystone
   backend, and the server will attempt to fetch user details (id, name, roles,
   groups) from the identity backend.

   If, however, the user does not exist in the backend, the server will
   respond with an appropriate HTTP error code.

   If the ``type`` attribute is not set to ``local`` in the local rule and no
   domain is specified, the user is deemed ephemeral and becomes a member of
   the identity provider's domain.

   An example of user object mapping to an existing local user:

   ::

       [
           {
               "local": [
                   {
                        "user": {
                            "name": "username",
                            "type": "local",
                            "domain": {
                                "name": "domain_name"
                            }
                        }
                   }
               ],
            }
        ]


   For attribute type and value mapping, identify the local resource type,
   attribute, and value:

   ::

       [
           {
               "local": [
                   {
                       "group": {
                           "id": "89678b"
                       }
                   }
               ],
           }
       ]

   This assigns authorization attributes, by way of role assignments on the
   specified group, to ephemeral users. The users are not added to the group,
   but for the duration of the token they will receive the same authorization
   as if they were.

   ::

       [
           {
               "local": [
                   {
                       "group_ids": "{0}"
                   }
               ],
            }
        ]

   It is also possible to map multiple groups by providing a list of group ids.
   Those group ids can also be white/blacklisted.

- ``remote`` (list of objects)

  At least one object must be included.

  If more than one object is included, the local attribute is applied only if
  all remote attributes match.

  The value identified by ``type`` is always passed through unless a constraint
  is specified using either ``any_one_of`` or ``not_one_of``.

  - ``type`` (string)

    This represents an assertion type keyword.

  - ``any_one_of`` (list of strings)

    This is mutually exclusive with ``not_any_of``.

    The rule is matched only if any of the specified strings appear in the
    remote attribute ``type``.

  - ``not_any_of`` (list of strings)

    This is mutually exclusive with ``any_one_of``.

    The rule is not matched if any of the specified strings appear in the
    remote attribute ``type``.

  - ``regex`` (boolean)

    If ``true``, then each string will be evaluated as a `regular expression
    <http://docs.python.org/2/library/re.html>`__ search against the remote
    attribute ``type``.

  The ``blacklist`` and ``whitelist`` rules are always used in conjunction with
  ``type``.

  - ``blacklist`` (list of strings)

    This is mutually exclusive with ``whitelist``.

    The rule works as a filter, removing any specified strings that are
    listed there from the remote attribute ``type``.

  - ``whitelist`` (list of strings)

    This is mutually exclusive with ``blacklist``.

    The rule works as a filter, allowing only the specified strings in
    the remote attribute ``type`` to be passed ahead.

Service Providers
-----------------

::

    /v3/OS-FEDERATION/service_providers

A service provider is a third party service that is trusted by the Identity
Service.

Required attributes:

- ``auth_url`` (string)

Specifies the protected URL where tokens can be retrieved once the user is
authenticated.

- ``sp_url`` (string)

Specifies the URL at the remote peer where assertion should be sent.

Optional attributes:

- ``description`` (string)

Describes the service provider

If a value is not specified by the client, the service may default this value
to ``null``.

- ``enabled`` (boolean)

Indicates whether bursting into this service provider is enabled by cloud
administrators. If set to ``false`` the SP will not appear in the catalog and
requests to generate an assertion will result in a 403 error.
If a value is not specified by the client, the service will default this to
``false``.

- ``relay_state_prefix`` (string)

Indicates the relay state prefix, used in the ECP wrapped SAML messages, by the
Service Provider.

If a value is not specified by the client, the service will default this value
to ``ss:mem:``.

APIs
====

.. include:: federation/identity-provider/idp.inc

.. include:: federation/mapping/mapping.inc

.. include:: federation/service-provider/sp.inc

.. include:: federation/projects-domains/projects-domains.inc

.. include:: federation/auth/auth.inc

.. include:: federation/assertion/assertion.inc
