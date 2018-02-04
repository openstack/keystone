.. -*- rst -*-

===============
 OS-REVOKE API
===============

This API provides a list of token revocations. Each event expresses a set of
criteria which describes a set of tokens that are no longer valid.
Requires v3.2+ of the Identity API.

What's New in v1.1
==================

* Use of expires_at has been deprecated in favor of using audit_id and audit_chain_id.
* Revocation events can use audit_id to revoke an individual token.
* Revocation events can use audit_chain_id to revoke all related tokens.
  A related token is defined by the first (non-rescoped) token. All tokens in the
  chain will have the same audit_chain_id.

API Resources
=============

Revocation Events
-----------------

Revocation events are objects that contain criteria used to evaluate token validity.
Tokens that match all the criteria of a revocation event are considered revoked,
and should not be accepted as proof of authorization for the user.

Revocation events do not have a unique identifier (id).

List revocation events
======================

.. rest_method::  GET /v3/OS-REVOKE/events

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-REVOKE/1.0/rel/events``

List revocation events.

The HTTP Date header returned in the response reflects the timestamp of the
most recently issued revocation event. Clients can then use this value in the
since query parameter to limit the list of events in subsequent requests.

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - since: since_query

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: parameters.yaml

   - events: revoke_events
   - issued_before: revoke_issued_before
   - user_id: revoke_user_id
   - audit_id: revoke_audit_id
   - audit_chain_id: revoke_audit_chain_id
   - domain_id: revoke_domain_id
   - project_id: revoke_project_id
   - role_id: revoke_role_id
   - OS-TRUST:trust_id: revoke_trust_id
   - OS-OAUTH1:consumer_id: revoke_consumer_id
   - expires_at: revoke_expires_at

Status Codes
~~~~~~~~~~~~

.. rest_status_code:: success ../v3/status.yaml

   - 200

Example
~~~~~~~

.. literalinclude:: samples/OS-REVOKE/list-revoke-response.json
   :language: javascript