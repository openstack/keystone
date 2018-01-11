.. -*- rst -*-

.. **Deprecated in v1.1**. This section is deprecated as the functionality is
   available in the core Identity API.

List projects a federated user can access
=========================================

.. rest_method::  GET /v3/OS-FEDERATION/projects

**Deprecated in v1.1**. Use core ``GET /auth/projects``. This call has the same
response format.

Returns a collection of projects to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a project and request a scoped token. Note that only enabled
projects will be returned.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/projects``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/projects-domains/parameters.yaml

   - links: links_projects
   - projects: projects

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/projects-domains/samples/project-list-response.json
   :language: javascript


List domains a federated user can access
========================================

.. rest_method::  GET /v3/OS-FEDERATION/domains

**Deprecated in v1.1**. Use core ``GET /auth/domains``. This call has the same
response format.

Returns a collection of domains to which the federated user has authorization
to access. To access this resource, an unscoped token is used, the user can
then select a domain and request a scoped token. Note that only enabled domains
will be returned.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/domains``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/projects-domains/parameters.yaml

   - domains: domains
   - links: links_domains

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: federation/projects-domains/samples/domain-list-response.json
   :language: javascript