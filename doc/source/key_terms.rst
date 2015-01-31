=========
Key Terms
=========

This document describes the different resource types that are available in
OpenStack's Identity Service.

Identity
========

The Identity portion of keystone includes ``Users`` and ``Groups``, and may be
backed by SQL or more commonly LDAP.

Users
-----

``Users`` represent an individual API consumer. A user itself must be owned by
a specific domain, and hence all user names are **not** globally unique, but
only unique to their domain.

Groups
------

``Groups`` are a container representing a collection of users. A group itself
must be owned by a specific domain, and hence all group names are **not**
globally unique, but only unique to their domain.

Resources
=========

The Identity portion of keystone includes ``Projects`` and ``Domains``, and
are commonly stored in an SQL backend.

Projects (Tenants)
------------------

``Projects`` (known as Tenants in v2.0) represent the base unit of
``ownership`` in OpenStack, in that all resources in OpenStack should be owned
by a specific project.
A project itself must be owned by a specific domain, and hence all project
names are **not** globally unique, but unique to their domain.
If the domain for a project is not specified, then it is added to the default
domain.

Domains
-------

``Domains`` are a high-level container for projects, users and groups. Each is
owned by exactly one domain. Each domain defines a namespace where certain an
API-visible name attribute exists. keystone provides a default domain, aptly
named 'Default'.

In the Identity v3 API, the uniqueness of attributes is as follows:

- Domain Name. Globally unique across all domains.

- Role Name. Globally unique across all domains.

- User Name. Unique within the owning domain.

- Project Name. Unique within the owning domain.

- Group Name. Unique within the owning domain.

Due to their container architecture, domains may be used as a way to delegate
management of OpenStack resources. A user in a domain may still access
resources in another domain, if an appropriate assignment is granted.


Assignment
==========

Roles
-----

``Roles`` dictate the level of authorization the end user can obtain. Roles
can be granted at either the domain or project level. Role can be assigned to
the individual user or at the group level. Role names are globally unique.

Role Assignments
----------------

A 3-tuple that has a ``Role``, a ``Resource`` and an ``Identity``.

What's needed to Authenticate?
==============================

Two pieces of information are required to authenticate with keystone, a
bit of ``Resource`` information and a bit of ``Identity``.

Take the following call POST data for instance:

.. code-block:: javascript

    {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "id": "0ca8f6",
                        "password": "secretsecret"
                    }
                }
            },
            "scope": {
                "project": {
                    "id": "263fd9"
                }
            }
        }
    }

The user (ID of 0ca8f6) is attempting to retrieve a token that is scoped to
project (ID of 263fd9).

To perform the same call with names instead of IDs, we now need to supply
information about the domain. This is because usernames are only unique within
a given domain, but user IDs are supposed to be unique across the deployment.
Thus, the auth request looks like the following:

.. code-block:: javascript

    {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "name": "acme"
                        }
                        "name": "userA",
                        "password": "secretsecret"
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "id": "1789d1"
                    },
                    "name": "project-x"
                }
            }
        }
    }

For both the user and the project portion, we must supply either a domain ID
or a domain name, in order to properly determine the correct user and project.

Alternatively, if we wanted to represent this as environment variables for a
command line, it would be:

.. code-block:: bash

    $ export OS_PROJECT_DOMAIN_ID=1789d1
    $ export OS_USER_DOMAIN_NAME=acme
    $ export OS_USERNAME=userA
    $ export OS_PASSWORD=secretsecret
    $ export OS_PROJECT_NAME=project-x

Note that the project the user it attempting to access must be in the same
domain as the user.

What is Scope?
==============

Scope is an overloaded term.

In reference to authenticating, as seen above, scope refers to the portion
of the POST data that dictates what ``Resource`` (project or domain) the user
wants to access.

In reference to tokens, scope refers to the effectiveness of a token,
i.e.: a `project-scoped` token is only useful on the project it was initially
granted for. A `domain-scoped` token may be used to perform domain-related
function.

In reference to users, groups, and projects, scope often refers to the domain
that the entity is owned by. i.e.: a user in domain X is scoped to domain X.
