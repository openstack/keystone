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

Lists all domains.

Normal response codes: 200
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - name: name
   - enabled: enabled

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name
   - links: links
   - enabled: enabled
   - domains: domains
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/domains-list-response.json
   :language: javascript


Create domain
=============

.. rest_method::  POST /v3/domains

Creates a domain.

Normal response codes: 201
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - enabled: enabled
   - description: description
   - name: name

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - name: name
   - links: links
   - enabled: enabled
   - id: id
   - description: description


Show domain details
===================

.. rest_method::  GET /v3/domains/{domain_id}

Shows details for a domain.

Normal response codes: 200
Error response codes: 413,405,404,403,401,400,503

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - name: name
   - links: links
   - enabled: enabled
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-show-response.json
   :language: javascript


Update domain
=============

.. rest_method::  PATCH /v3/domains/{domain_id}

Updates a domain.

Normal response codes: 200
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - enabled: enabled
   - description: description
   - name: name
   - domain_id: domain_id

Request Example
---------------

.. literalinclude:: ./samples/admin/domain-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - domain: domain
   - name: name
   - links: links
   - enabled: enabled
   - id: id
   - description: description

Response Example
----------------

.. literalinclude:: ./samples/admin/domain-update-response.json
   :language: javascript


Delete domain
=============

.. rest_method::  DELETE /v3/domains/{domain_id}

Deletes a domain.

To minimize the risk of accidentally deleting a domain, you must
first disable the domain by using the update domain method.

When you delete a domain, this call also deletes all entities owned
by it, such as users, groups, and projects, and any credentials and
granted roles that relate to those entities.

(Since v3.6) The deletion of a non-leaf domain in a domain
hierarchy tree is not allowed and fails with a ``Bad Request
(400)`` response code.

If you try to delete an enabled domain, this call returns the
``Forbidden (403)`` response code.

Normal response codes: 204
Error response codes: 413,415,405,404,403,401,400,503,409

Request
-------

.. rest_parameters:: parameters.yaml

   - domain_id: domain_id
