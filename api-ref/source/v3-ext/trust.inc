.. -*- rst -*-

==============
 OS-TRUST API
==============

Trusts provide project-specific role delegation between users, with optional impersonation.

API Resources
=============

Trusts
------

A trust represents a user’s (the `trustor`) authorization to delegate
roles to another user (the `trustee`), and optionally allow the trustee
to impersonate the trustor. After the trustor has created a trust, the
trustee can specify the trust’s id attribute as part of an authentication
request to then create a token representing the delegated authority of the trustor.

The trust contains constraints on the delegated attributes. A token created
based on a trust will convey a subset of the trustor’s roles on the specified
project. Optionally, the trust may only be valid for a specified time period,
as defined by ``expires_at``. If no ``expires_at`` is specified, then the trust is
valid until it is explicitly revoked.

The ``impersonation`` flag allows the trustor to optionally delegate impersonation
abilities to the trustee. To services validating the token, the trustee will
appear as the trustor, although the token will also contain the ``impersonation`` flag
to indicate that this behavior is in effect.

A ``project_id`` may not be specified without at least one role, and vice versa.
In other words, there is no way of implicitly delegating all roles to a trustee, in
order to prevent users accidentally creating trust that are much more broad in scope
than intended. A trust without a ``project_id`` or any delegated roles is unscoped,
and therefore does not represent authorization on a specific resource.

Trusts are immutable. If the trustee or trustor wishes to modify the attributes
of the trust, they should create a new trust and delete the old trust. If a trust
is deleted, any tokens generated based on the trust are immediately revoked.

If the trustor loses access to any delegated attributes, the trust becomes immediately
invalid and any tokens generated based on the trust are immediately revoked.

Trusts can also be chained, meaning, a trust can be created by using a trust scoped
token.

For more information, see `Use trusts <http://docs.openstack.org
/admin-guide/keystone_use_trusts.html>`_.

Consuming a trust
=================

.. rest_method::  POST /v3/auth/tokens

Consuming a trust effectively assumes the scope as delegated in the trust. No
other scope attributes may be specified.

The user specified by authentication must match the trust’s ``trustee_user_id``
attribute.

If the trust has the ``impersonation`` attribute set to `true`, then the resulting
token’s user attribute will also represent the trustor, rather than the
authenticating user (the trustee).

Request Example
----------------

.. literalinclude:: samples/OS-TRUST/trust-auth-request.json
   :language: javascript

A token created from a trust will have an ``OS-TRUST:trust`` section containing the
``id`` of the trust, the ``impersonation`` flag, the ``trustee_user_id`` and the
``trustor_user_id``.

Response Example
----------------

.. literalinclude:: samples/OS-TRUST/trust-auth-trust-response.json
   :language: javascript

A token created from a redelegated trust will have an ``OS-TRUST:trust`` section
containing the same fields as a regular trust token, only ``redelegated_trust_id`` and
``redelegation_count`` are added.

Response Example
----------------

.. literalinclude:: samples/OS-TRUST/trust-auth-redelegated-response.json
   :language: javascript


Create trust
============

.. rest_method::  POST /v3/OS-TRUST/trusts

Creates a trust.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trusts

Response codes: 201, 400, 401, 403, 404, 405, 409, 413, 415, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust: trust
   - impersonation: impersonation
   - trustee_user_id: trustee_user_id
   - trustor_user_id: trustor_user_id
   - allow_redelegation: allow_redelegation
   - expires_at: trust_expires_at
   - project_id: trust_project_id
   - redelegated_trust_id: redelegated_trust_id
   - redelegation_count: redelegation_count
   - remaining_uses: remaining_uses
   - roles: trust_roles

Request Example
---------------

Status: 201 Created

.. literalinclude:: samples/OS-TRUST/trust-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - trust: trust
   - id: id
   - impersonation: impersonation
   - trustee_user_id: trustee_user_id
   - trustor_user_id: trustor_user_id
   - allow_redelegation: allow_redelegation
   - expires_at: trust_expires_at
   - project_id: trust_project_id
   - redelegated_trust_id: redelegated_trust_id
   - redelegation_count: redelegation_count
   - remaining_uses: remaining_uses
   - roles: trust_roles
   - roles_links: roles_links
   - links: trust_links

Response Example
----------------

Status: 201 Created

.. literalinclude:: samples/OS-TRUST/trust-create-response.json
   :language: javascript

List trusts
===========

.. rest_method:: GET /v3/OS-TRUST/trusts

Lists all trusts.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trusts

Response codes: 200, 400, 401, 403, 404, 405, 413, 503

The following optional query strings are supported:

- ``page``
- ``per_page`` (default 30)
- ``trustor_user_id``
- ``trustee_user_id``

In order to list trusts for a given trustor, filter the collection using a query string
(e.g., ``?trustor_user_id={user_id}``).

::

   GET /v3/OS-TRUST/trusts?trustor_user_id=a0fdfd

In order to list trusts for a given trustee, filter the collection using a query string
(e.g., ``?trustee_user_id={user_id}``).

::

   GET /v3/OS-TRUST/trusts?trustee_user_id=86c0d5

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - trust: trust
   - id: id
   - impersonation: impersonation
   - trustee_user_id: trustee_user_id
   - trustor_user_id: trustor_user_id
   - allow_redelegation: allow_redelegation
   - expires_at: trust_expires_at
   - project_id: trust_project_id
   - redelegated_trust_id: redelegated_trust_id
   - redelegation_count: redelegation_count
   - remaining_uses: remaining_uses
   - roles: trust_roles
   - roles_links: roles_links
   - links: trust_links

Response Example
----------------

Status: 200 OK

.. literalinclude:: samples/OS-TRUST/trust-list-response.json
   :language: javascript


Get trust
=========

.. rest_method:: GET /v3/OS-TRUST/trusts/{trust_id}

Gets the trust information for ``{trust_id}``.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trust

Response codes: 200, 400, 401, 403, 404, 405, 413, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust_id: trust_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - trust: trust
   - id: id
   - impersonation: impersonation
   - trustee_user_id: trustee_user_id
   - trustor_user_id: trustor_user_id
   - allow_redelegation: allow_redelegation
   - expires_at: trust_expires_at
   - project_id: trust_project_id
   - redelegated_trust_id: redelegated_trust_id
   - redelegation_count: redelegation_count
   - remaining_uses: remaining_uses
   - roles: trust_roles
   - roles_links: roles_links
   - links: trust_links

Response Example
----------------

Status: 200 OK

.. literalinclude:: samples/OS-TRUST/trust-get-response.json
   :language: javascript


Delete trust
============

.. rest_method:: DELETE /v3/OS-TRUST/trusts/{trust_id}

Deletes a trust with ``{trust_id}``.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trust

Response codes: 204, 400, 401, 403, 404, 405, 409, 413, 415, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust_id: trust_id

Response Example
----------------

Status: 204 No Content


List roles delegated by a trust
===============================

.. rest_method:: GET /v3/OS-TRUST/trusts/{trust_id}/roles

Lists roles delegated by a trust with ``{trust_id}``.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trust_roles

Response codes: 200, 400, 401, 403, 404, 405, 413, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust_id: trust_id

Response Example
----------------

Status: 200 OK

.. literalinclude:: samples/OS-TRUST/trust-list-roles-delegated-response.json
   :language: javascript


Check if a role is delegated by a trust
=======================================

.. rest_method:: HEAD /v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}

Checks if a role is delegated by a trust.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trust_role

Response Codes: 200, 400, 401, 403, 404, 405, 413, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust_id: trust_id
   - role_id: role_id

Response Example
----------------

Status: 200 OK


Get role delegated by a trust
=============================

.. rest_method:: GET /v3/OS-TRUST/trusts/{trust_id}/roles/{role_id}

Gets a role with delegated by a trust.

Relationship: http://docs.openstack.org/api/openstack-identity/3/ext/OS-TRUST/1.0/rel/trust_role

Response Codes: 200, 400, 401, 403, 404, 405, 413, 503

Request
-------

.. rest_parameters:: parameters.yaml

   - trust_id: trust_id
   - role_id: role_id

Response Example
----------------

Status: 200 OK

.. literalinclude:: samples/OS-TRUST/trust-get-role-delegated-response.json
   :language: javascript
