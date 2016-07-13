.. -*- rst -*-

===================
OS-KSCRUD extension
===================

Supports password changing for a user by themselves

Change user's own password
==========================

.. rest_method::  PATCH /v2.0/OS-KSCRUD/users/{userId}

Changes user's own password and returns the new token

Normal response codes: 200

Request
-------

.. rest_parameters:: parameters.yaml

   - userId: userId
   - user: user
   - original_password: original_password
   - password: new_password
