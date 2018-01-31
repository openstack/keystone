.. -*- rst -*-

=======================
Application Credentials
=======================

Application credentials provide a way to delegate a user's authorization to an
application without sharing the user's password authentication. This is a
useful security measure, especially for situations where the user's
identification is provided by an external source, such as LDAP or a
single-sign-on service. Instead of storing user passwords in config files, a
user creates an application credential for a specific project, with all or a
subset of the role assignments they have on that project, and then stores the
application credential identifier and secret in the config file.

Multiple application credentials may be active at once, so you can easily
rotate application credentials by creating a second one, converting your
applications to use it one by one, and finally deleting the first one.

Application credentials are limited by the lifespan of the user that created
them. If the user is deleted, disabled, or loses a role assignment on a
project, the application credential is deleted.

Authenticating with an Application Credential
=============================================

.. rest_method::  POST /v3/auth/tokens

To authenticate with an application credential, specify
"application_credential" as the auth method. You are not allowed to request a
scope, as the scope is retrieved from the application credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/auth_tokens``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - identity: identity
   - methods: auth_methods_application_credential
   - application_credential: request_application_credential_body_required
   - id: request_application_credential_auth_id_body_not_required
   - name: request_application_credential_auth_name_body_not_required
   - secret: request_application_credential_auth_secret_body_required
   - user: request_application_credential_user_body_not_required

Example
~~~~~~~

An application credential can be identified by an ID:

.. literalinclude:: samples/admin/auth-application-credential-id-request.json
   :language: javascript

It can also be identified by its name and a user object:

.. literalinclude:: samples/admin/auth-application-credential-name-request.json
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - X-Subject-Token: X-Subject-Token
   - domain: domain
   - methods: auth_methods
   - user: user
   - token: token
   - expires_at: expires_at
   - project: project
   - catalog: catalog
   - roles: roles
   - audit_ids: audit_ids
   - issued_at: issued_at
   - id: user_id
   - name: user_name
   - application_credential_restricted: auth_application_credential_restricted_body

Example
~~~~~~~

.. literalinclude:: samples/admin/auth-application-credential-response.json
   :language: javascript

A token created with an application credential will have the scope and roles
designated by the application credential.

Create application credential
=============================

.. rest_method::  POST /v3/users/{user_id}/application_credentials

Creates an application credential for a user on the project to which they are
currently scoped.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/application_credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: request_application_credential_user_id_path_required
   - application_credential: request_application_credential_body_required
   - name: request_application_credential_name_body_required
   - secret: request_application_credential_secret_body_not_required
   - description: request_application_credential_description_body_not_required
   - expires_at: request_application_credential_expires_at_body_not_required
   - roles: request_application_credential_roles_body_not_required
   - unrestricted: request_application_credential_unrestricted_body_not_required

Example
~~~~~~~

.. literalinclude:: samples/admin/application-credential-create-request.json
   :language: javascript

Response
--------

.. rest_status_code:: success status.yaml

   - 201

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - application_credential: response_application_credential_body
   - id: response_application_credential_id_body
   - name: response_application_credential_name_body
   - secret: response_application_credential_secret_body
   - description: response_application_credential_description_body
   - expires_at: response_application_credential_expires_at_body
   - project_id: response_application_credential_project_id_body
   - roles: response_application_credential_roles_body
   - unrestricted: response_application_credential_unrestricted_body
   - links: link_response_body

Example
~~~~~~~

.. literalinclude:: samples/admin/application-credential-create-response.json
   :language: javascript

List application credentials
=============================

.. rest_method::  GET /v3/users/{user_id}/application_credentials

List all application credentials for a user.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/application_credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: request_application_credential_user_id_path_required

Response
--------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - application_credential: response_application_credential_body
   - id: response_application_credential_id_body
   - name: response_application_credential_name_body
   - description: response_application_credential_description_body
   - expires_at: response_application_credential_expires_at_body
   - project_id: response_application_credential_project_id_body
   - roles: response_application_credential_roles_body
   - unrestricted: response_application_credential_unrestricted_body
   - links: link_collection

Example
~~~~~~~

.. literalinclude:: samples/admin/application-credential-list-response.json
   :language: javascript

Show application credential details
===================================

.. rest_method::  GET /v3/users/{user_id}/application_credentials/{application_credential_id}

Show details of an application credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/application_credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: request_application_credential_user_id_path_required
   - application_credential_id: request_application_credential_id_path_required

Response
--------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - application_credential: response_application_credential_body
   - id: response_application_credential_id_body
   - name: response_application_credential_name_body
   - description: response_application_credential_description_body
   - expires_at: response_application_credential_expires_at_body
   - project_id: response_application_credential_project_id_body
   - roles: response_application_credential_roles_body
   - unrestricted: response_application_credential_unrestricted_body
   - links: link_response_body

Example
~~~~~~~

.. literalinclude:: samples/admin/application-credential-get-response.json
   :language: javascript

Delete application credential
=============================

.. rest_method::  DELETE /v3/users/{user_id}/application_credentials/{application_credential_id}

Delete an application credential.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/rel/application_credentials``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - user_id: request_application_credential_user_id_path_required
   - application_credential_id: request_application_credential_id_path_required

Response
--------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404
