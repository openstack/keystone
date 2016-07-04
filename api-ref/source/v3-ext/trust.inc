.. -*- rst -*-

==============
 OS-TRUST API 
==============

Creates a trust.

A trust is an OpenStack Identity extension that enables delegation
and, optionally, impersonation through ``keystone``. A trust
extension defines a relationship between a trustor and trustee. A
trustor is the user who delegates a limited set of their own rights
to another user, known as the trustee, for a limited time.

The trust can eventually enable the trustee to impersonate the
trustor. For security reasons, some safety measures are added. For
example, if a trustor loses a given role, the API automatically
revokes any trusts and the related tokens that the user issued with
that role.

For more information, see `Use trusts <http://docs.openstack.org
/admin-guide/keystone_use_trusts.html>`_.


Create trust
============

.. rest_method::  POST /v3/OS-TRUST/trusts

Creates a trust.

Error response codes:201,413,415,405,404,403,401,400,503,409,

Request
-------

.. rest_parameters:: parameters.yaml

   - impersonation: impersonation
   - trust: trust
   - trustor_user_id: trustor_user_id
   - name: name
   - roles: roles
   - oauth_expires_at: oauth_expires_at
   - remaining_uses: remaining_uses
   - trustee_user_id: trustee_user_id
   - project_id: project_id

Request Example
---------------

.. literalinclude:: samples/OS-TRUST/trust-create-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - impersonation: impersonation
   - roles_links: roles_links
   - trust: trust
   - trustor_user_id: trustor_user_id
   - name: name
   - links: links
   - oauth_expires_at: oauth_expires_at
   - remaining_uses: remaining_uses
   - trustee_user_id: trustee_user_id
   - roles: roles
   - project_id: project_id
   - id: id
