.. -*- rst -*-

.. **Deprecated in v1.1**. This section is deprecated as the functionality is
   available in the core Identity API.

List projects a federated user can access
=========================================

.. rest_method::  GET /v3/OS-FEDERATION/projects

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/projects``

Normal response codes: 200

**Deprecated in v1.1**. Use core ``GET /auth/projects``. This call has the same
response format.

Returns a collection of projects to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a project and request a scoped token. Note that only enabled
projects will be returned.

Response
--------

.. rest_parameters:: federation/projects-domains/parameters.yaml

   - links: links_projects
   - projects: projects

Response Example
----------------

.. literalinclude:: federation/projects-domains/samples/project-list-response.json
   :language: javascript


List domains a federated user can access
========================================

.. rest_method::  GET /v3/OS-FEDERATION/domains

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/domains``

Normal response codes: 200

**Deprecated in v1.1**. Use core ``GET /auth/domains``. This call has the same
response format.

Returns a collection of domains to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a domain and request a scoped token. Note that only enabled domains
will be returned.

Response
--------

.. rest_parameters:: federation/projects-domains/parameters.yaml

   - domains: domains
   - links: links_domains

Response Example
----------------

.. literalinclude:: federation/projects-domains/samples/domain-list-response.json
   :language: javascript
