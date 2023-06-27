.. -*- rst -*-

===============
 OS-OAUTH2 API
===============

Provide the ability for identity users to delegate roles to third party
consumers via the `OAuth 2.0 Client Credentials grant specification
<https://oauth.net/2/grant-types/client-credentials/>`__.
Requires v3.0+ of the Identity API. An OAuth2-derived access token will
provide a means of acting on behalf of the authorizing user.

Overview
========

Definitions
-----------

- *User:* The end-users who use Identity API service, the entity whose role(s)
  will be delegated, and the entity that registers Clients.

- *Client:* An application making protected resource requests on behalf of the
  User. The credentials of the client are created though the Application
  Credentials API.

- *Access Token:* A token used by the Client to make protected resource
  requests with the delegated roles.

Delegated Authentication Flow
-----------------------------

Delegated Authentication via OAuth 2.0 is done in four steps:

#. An Identity API service User creates an `application credential`_.

#. The Client authenticates with the authorization server on the Keystone and
   requests a new Access Token.

#. The Client uses the Access Token to make requests for OpenStack Service
   APIs.

#. Keystone Middleware validates the Access Token in an API request to obtain
   its metadata and validity, and forwards the request to the OpenStack service
   if the token is active.

.. _application credential: https://docs.openstack.org/api-ref/identity/v3/index.html?expanded=create-application-credential-detail#create-application-credential

Create Access Token
===================

.. rest_method::  POST /identity/v3/OS-OAUTH2/token

Enables a user to create an access token.
The user makes a request to the token endpoint by adding the following
parameters using the "application/x-www-form-urlencoded" format with
a character encoding of UTF-8 in the HTTP request entity-body. And the
request should use the basic authentication header which contains the
application credentials information to authenticate a user through the
authorization server.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-OAUTH2/1.0/rel/token``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

    - grant_type: request_token_grant_type_body_required

Example
~~~~~~~

.. literalinclude:: ./samples/OS-OAUTH2/token-create-request.txt
   :language: javascript

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

    - access_token: response_token_access_token_body
    - token_type: response_token_token_type_body
    - expires_in: response_token_expires_in_body

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

.. rest_status_code:: error ../v3/status.yaml

   - 400
   - 401
   - 404
   - 500

Status: 200 OK

Example
~~~~~~~

.. literalinclude:: ./samples/OS-OAUTH2/token-create-response.json
   :language: javascript
