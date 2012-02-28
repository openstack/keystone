..
      Copyright 2011-2012 OpenStack, LLC
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

========
Backends
========

Keystone supports multiple types of data stores for things like users, tenants, and
tokens, including SQL, LDAP, and memcache.

SQL
===

In the default backend configuration (SQL-only), Keystone depends on the following database tables.

``users``
---------

``id``
    Auto-incremented primary key.
``name``
    Unqiue username used for authentication via ``passwordCredentials``.
``password``
    Password used for authentication via ``passwordCredentials``.

    Salted and hashed using ``passlib``.
``email``
    Email address (uniqueness is expected, but not enforced).
``enabled``
    If false, the user is unable to authenticate and the user's tokens will fail validation.
``tenant_id``
    Default tenant for the user.

``tokens``
----------

``id``
    The actual token provided after successful authentication (*plaintext*).
``user_id``
    References the user who owns the token.
``tenant_id``
    (*optional*) References the tenant the token is scoped to.
``expires``
    Indicates the expiration date of the token, after which the token can no longer be validated successfully.

``tenants``
-----------

``id``
    Auto-incremented primary key.
``name``
    Unique string identifying the tenant.
``desc``
    Description of the tenant.
``enabled``
    If false, users are unable to scope to the tenant.

``roles``
---------

``id``
    Auto-incremented primary key.
``name``
    Name of the role.

    If the role is owned by a service, the role name **must** follow the convention::

        serviceName:roleName
``desc``
    Description of the role.
``service_id``
    (*optional*) References the service that owns the role.

``user_roles``
--------------

Maps users to the roles that have been granted to them (*optionally*, within the scope of a tenant).

``id``
    Auto-incremented primary key.
``user_id``
    References the user the role is granted to.
``role_id``
    References the granted role.
``tenant_id``
    (*optional*) References a tenant upon which this grant is applies.

``services``
------------

``id``
    Auto-incremented primary key.
``name``
    Unique name of the service.
``type``
    Indicates the type of service (e.g. ``compute``, ``object``, ``identity``, etc).

    This can also be extended to support non-core services. Extended services
    follow the naming convention ``extension:type`` (e.g. ``dnsextension:dns``).
``desc``
    Describes the service.
``owner_id``
    (*optional*) References the user who owns the service.

``credentials``
---------------

Currently only used for Amazon EC2 credential storage, this table is designed to support multiple
types of credentials in the future.

``id``
    Auto-incremented primary key.
``user_id``
    References the user who owns the credential.
``tenant_id``
    References the tenant upon which the credential is valid.
``types``
    Indicates the type of credential (e.g. ``Password``, ``APIKey``, ``EC2``).
``key``
    Amazon EC2 access key.
``secret``
    Amazon EC2 secret key.

``endpoints``
-------------

Tenant-specific endpoints map endpoint templates to specific tenants.
The ``tenant_id`` which appears here replaces the
``%tenant_id%`` template variable in the specified endpoint template.

``id``
    Auto-incremented primary key.
``tenant_id``
    References the tenant this endpoint applies to.
``endpoint_template_id``
    The endpoint template to appear in the user's service catalog.

``endpoint_templates``
----------------------

A multi-purpose model for the service catalog which can be:

- Provided to users of a specific tenants via ``endpoints``, when ``is_global`` is false.
- Provided to all users as-is, when ``is_global`` is true.

``id``
    Auto-incremented primary key.
``region``
    Identifies the geographic region the endpoint is physically located within.
``service_id``
    TODO: References the service which owns the endpoints?
``public_url``
    Appears in the service catalog [#first]_.

    Represents an endpoint available on the public Internet.
``admin_url``
    Appears in the service catalog [#first]_.

    Users of this endpoint must have an Admin or ServiceAdmin role.
``internal_url``
    Appears in the service catalog [#first]_.

    Represents an endpoint on an internal, unmetered network.
``enabled``
    If false, this endpoint template will not appear in the service catalog.
``is_global``
    If true, this endpoint can not be mapped to tenant-specific endpoints, and ``%tenant_id%`` will not be substituted in endpoint URL's. Additionally, this endpoint will appear for all users.
``version_id``
    Identifies the version of the API contract that endpoint supports.
``version_list``
    A URL which lists versions supported by the endpoint.
``version_info``
    A URL which provides detailed version info regarding the service.

.. [#first] ``%tenant_id%`` may be replaced by actual tenant references, depending on the value of ``is_global`` and the existence of a corresponding ``endpoints`` record.
