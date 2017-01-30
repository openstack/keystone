.. -*- rst -*-

=========
 Domains
=========

A domain is a collection of users, groups, and projects. Each group
and project is owned by exactly one domain.

Each domain defines a namespace where certain API-visible name
attributes exist, which affects whether those names must be
globally unique or unique within that domain. In the Identity API,
the uniqueness of these attributes is as follows:

- *Domain name*. Globally unique across all domains.

- *Role name*. Globally unique across all domains.

- *User name*. Unique within the owning domain.

- *Project name*. Unique within the owning domain.

- *Group name*. Unique within the owning domain.


List domains
============

.. rest_method::  GET /v3/domains

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domains``

Lists all domains.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - name: domain_name_query
   - enabled: domain_enabled_query

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domains: domains
   - description: domain_description_response_body
   - enabled: domain_enabled_response_body
   - id: domain_id_response_body
   - links: domain_link_response_body
   - name: domain_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/domains-list-response.json
   :language: javascript


Create domain
=============

.. rest_method::  POST /v3/domains

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domains``

Creates a domain.

Normal response codes: 201

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - enabled: domain_enabled_request_body
   - description: domain_description_request_body
   - name: domain_name_request_body
 
Request Example
---------------

.. literalinclude:: ./samples/admin/domain-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - description: domain_description_response_body
   - enabled: domain_enabled_response_body
   - id: domain_id_response_body
   - links: domain_link_response_body
   - name: domain_name_response_body


Show domain details
===================

.. rest_method::  GET /v3/domains/{domain_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domains``

Shows details for a domain.

Normal response codes: 200

Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - description: domain_description_response_body
   - enabled: domain_enabled_response_body
   - id: domain_id_response_body
   - links: domain_link_response_body
   - name: domain_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-show-response.json
   :language: javascript


Update domain
=============

.. rest_method::  PATCH /v3/domains/{domain_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain``

Updates a domain.

Normal response codes: 200

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
   - domain: domain
   - enabled: domain_enabled_update_request_body
   - description: domain_description_update_request_body
   - name: domain_name_update_request_body

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - description: domain_description_response_body
   - enabled: domain_enabled_response_body
   - id: domain_id_response_body
   - links: domain_link_response_body
   - name: domain_name_response_body

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-update-response.json
   :language: javascript


Delete domain
=============

.. rest_method::  DELETE /v3/domains/{domain_id}

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/domain``

Deletes a domain.

To minimize the risk of accidentally deleting a domain, you must
first disable the domain by using the update domain method.

When you delete a domain, this call also deletes all entities owned
by it, such as users, groups, and projects, and any credentials and
granted roles that relate to those entities.

If you try to delete an enabled domain, this call returns the
``Forbidden (403)`` response code.

Normal response codes: 204

Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id_path
