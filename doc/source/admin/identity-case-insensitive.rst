==============================
Case-Insensitivity in keystone
==============================

Keystone currently handles the case-sensitivity for the naming of each
resource a bit differently, depending on the resource itself, and the
backend used. For example, depending on whether a user is backed by
local SQL or LDAP, the case-sensitivity can be different. When it is
case-insensitive, the casing will be preserved. For instance, a
project with the name "myProject" will not end up changing to either all
lower or upper case.

Resources in keystone
=====================

Below are examples of case-insensitivity in keystone for users, projects,
and roles.

Users
-----

If a user with the name "MyUser" already exists, then the following call
which creates a new user by the name of "myuser" will return a
``409 Conflict``:

.. code-block:: console

    POST /v3/users {name: myuser}

Projects
--------

If a project with the name "Foobar" already exists, then the following call
which creates a new project by the name of "foobar" will return a
``409 Conflict``:

.. code-block:: console

    POST /v3/projects {name: foobar}

Roles
-----

Role names are case-insensitive. for example, when keystone bootstraps default
roles, it creates "admin", "member", and "reader". If another role, "Member"
(note the upper case 'M') is created, keystone will return a ``409 Conflict``
since it considers the name "Member" equivalent to "member". Note that case
is preserved in this event.

Backends
========

For each of these examples, we will refer to an existing project with the
name "mYpRoJeCt" and user with the name "mYuSeR". The examples here are
exaggerated to help display the case handling for each backend.

MySQL & SQLite
--------------

By default, MySQL/SQLite are case-insensitive but case-preserving for
`varchar`. This means that setting a project name of "mYpRoJeCt" will cause
attempting to create a new project named "myproject" to fail with keystone
returning a ``409 Conflict``. However, the original value of "mYpRoJeCt" will
still be returned since case is preserved.

Users will be treated the same, if another user is added with the name
"myuser", keystone will respond with ``409 Conflict`` since another user with
the (same) name exists ("mYuSeR").

PostgreSQL
----------

PostgreSQL is case-sensitive by default, so if a project by the name of
"myproject" is created with the existing "mYpRoJeCt", it will be created
successfully.

LDAP
----

By default, LDAP DNs are case-insensitive, so the example with users under
MySQL will apply here as well.