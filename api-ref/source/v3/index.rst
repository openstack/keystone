:tocdepth: 3

---------------------------
 Identity API v3 (CURRENT)
---------------------------

The Identity service generates authentication tokens that permit access to the
OpenStack services REST APIs. Clients obtain this token and the URL endpoints
for other service APIs by supplying their valid credentials to the
authentication service.

Each time you make a REST API request to an OpenStack service, you supply your
authentication token in the X-Auth-Token request header.

Like most OpenStack projects, OpenStack Identity protects its APIs by defining
policy rules based on a role-based access control (RBAC) approach.

The Identity service configuration file sets the name and location of a JSON
policy file that stores these rules.

Note that the V3 API implements HEAD for all GET requests. Each HEAD request
contains the same headers and HTTP status code as the corresponding GET API.

For information about Identity API protection, see
`Identity API protection with role-based access control (RBAC)
<https://docs.openstack.org/keystone/latest/admin/identity-service-api-protection.html>`_
in the OpenStack Cloud Administrator Guide.

==========================
What's New in Version 3.11
==========================

- New endpoint /v3/limits-model for discovering the limit model in effect
- New description field in registered and project limits
- New project_id filters for project limits
- New parameter include_limits for project detail query

==========================
What's New in Version 3.10
==========================

- Introduction of the Application Credentials API.
- Introduction of an experimental Unified Limits API.
- Ability to grant system role assignments and obtain system-scoped tokens.

=========================
What's New in Version 3.9
=========================

- Addition of ``tags`` attribute to project.
- New APIs to interact with the ``tags`` attribute.

=========================
What's New in Version 3.8
=========================

- Allow a service user to fetch a token that has expired.
- Add a ``password_expires_at`` query parameter to user list and users in
  group list.

=========================
What's New in Version 3.7
=========================

- Addition of the ``password_expires_at`` field to the user response object.
- Introduce a flag to bypass expiration and revocation checking.

=========================
What's New in Version 3.6
=========================

- Listing role assignments for a tree of projects.
- Setting the project ``is_domain`` attribute enables a project to behave as
  a domain.
- Addition of the ``is_domain`` field to project scoped token response that
  represents whether a project is acting as a domain.
- Enable or disable a subtree in the project hierarchy.
- Delete a subtree in the project hierarchy.
- Additional identifier for tokens scoped to the designated ``admin project``.
- Addition of ``domain_id`` filter to list user projects
- One role can imply another via role_inference rules.
- Enhance list role assignment to optionally provide names of entities.
- The defaults for domain-specific configuration options can be retrieved.
- Assignments can be specified as inherited, causing the assignment to be
  placed on any sub-projects.
- Support for domain specific roles.
- Support ``enabled`` and ``id`` as optional attributes to filter identity
  providers when listing.

=========================
What's New in Version 3.5
=========================

- Addition of ``type`` optional attribute to list credentials.
- Addition of ``region_id`` optional attribute to list endpoints.
- Addition of ``is_domain`` optional attribute to projects. Setting this
  currently has no effect, it is reserved for future use.

=========================
What's New in Version 3.4
=========================

- For tokenless authorization, the scope information may be set in the
  request headers.
- Addition of ``parent_id`` optional attribute to projects. This enables the
  construction of a hierarchy of projects.
- Addition of domain specific configuration management for a domain entity.
- Removal of ``url`` optional attribute for ``regions``. This attribute was
  only used for the experimental phase of keystone-to-keystone federation and
  has been superseded by making service provider entries have its own entry in
  the service catalog.
- The JSON Home support now will indicate the status of resource if it is not
  stable and current.

=========================
What's New in Version 3.3
=========================

These features are considered stable as of September 4th, 2014.

- Addition of ``name`` optional variable to be included from service definition
  into the service catalog.
- Introduced a stand alone call to retrieve a service catalog.
- Introduced support for JSON Home.
- Introduced a standard call to retrieve possible project and domain scope
  targets for a token.
- Addition of ``url`` optional attribute for ``regions``.

=========================
What's New in Version 3.2
=========================

These features are considered stable as of January 23, 2014.

- Introduced a mechanism to opt-out from catalog information during
  token validation
- Introduced a region resource for constructing a hierarchical
  container of groups of service endpoints
- Inexact filtering is supported on string attributes
- Listing collections may indicate only a subset of the data has been
  provided if a particular deployment has limited the number of entries
  a query may return

=========================
What's New in Version 3.1
=========================

These features are considered stable as of July 18, 2013.

- A token without an explicit scope of authorization is issued if the user does
  not specify a project and does not have authorization on the project
  specified by their default project attribute
- Introduced a generalized call for getting role assignments, with filtering
  for user, group, project, domain and role
- Introduced a mechanism to opt-out from catalog information during token
  creation
- Added optional bind information to token structure

=========================
What's New in Version 3.0
=========================

These features are considered stable as of February 20, 2013.

- Former "Service" and "Admin" APIs (including CRUD operations previously
  defined in the v2 OS-KSADM extension) are consolidated into a single core API
- "Tenants" are now known as "projects"
- "Groups": a container representing a collection of users
- "Domains": a high-level container for projects, users and groups
- "Policies": a centralized repository for policy engine rule sets
- "Credentials": generic credential storage per user (e.g. EC2, PKI, SSH, etc.)
- Roles can be granted at either the domain or project level
- User, group and project names only have to be unique within their owning
  domain
- Retrieving your list of projects (previously ``GET /tenants``) is now
  explicitly based on your user ID: ``GET /users/{user_id}/projects``
- Tokens explicitly represent user+project or user+domain pairs
- Partial updates are performed using the HTTP ``PATCH`` method
- Token ID values no longer appear in URLs

=============
Relationships
=============

The entries within the operations below contain a relationship link, which
appears as a valid URI, however these are actually
URN (Uniform Resource Name), which are similar to GUID except it uses a URI
syntax so that it is easier to be read. These links do not resolve to
anything valid, but exist to show a relationship.

=======================
Identity API Operations
=======================

This page lists the Identity API operations in the following order:

* `Authentication and token management`_
* `Application Credentials`_
* `Credentials`_
* `Domains`_
* `Domain configuration`_
* `Groups`_
* `Policies`_
* `Projects`_
* `Project Tags`_
* `Regions`_
* `Roles`_
* `System Role Assignments`_
* `Service catalog and endpoints`_
* `Unified Limits`_
* `Users`_
* `OS-INHERIT`_
* `OS-PKI`_

.. rest_expand_all::

.. include:: authenticate-v3.inc
.. include:: application-credentials.inc
.. include:: credentials.inc
.. include:: domains.inc
.. include:: domains-config-v3.inc
.. include:: groups.inc
.. include:: inherit.inc
.. include:: os-pki.inc
.. include:: policies.inc
.. include:: projects.inc
.. include:: project-tags.inc
.. include:: regions-v3.inc
.. include:: roles.inc
.. include:: system-roles.inc
.. include:: service-catalog.inc
.. include:: unified_limits.inc
.. include:: users.inc
