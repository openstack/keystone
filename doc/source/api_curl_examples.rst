..
      Copyright 2011-2012 OpenStack Foundation
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

=======================
API Examples using Curl
=======================

--------------------------
v3 API Examples Using Curl
--------------------------

.. note::

   Following are some API examples using curl. Note that these examples are not
   automatically generated. They can be outdated as things change and are subject
   to regular updates and changes.


GET /
=====

Discover API version information, links to documentation (PDF, HTML, WADL),
and supported media types:

.. WARNING::

    The v2.0 portion of this response will be removed in the T release. It is
    only advertised here because the v2.0 API supports the ec2tokens API until
    the T release. All other functionality of the v2.0 has been removed as of
    the Queens release. Use v3 for all functionality as it is more complete and
    secure.

.. code-block:: bash

    $ curl "http://localhost:5000"

.. code-block:: javascript

    {
        "versions": {
            "values": [
                {
                    "id": "v3.10",
                    "links": [
                        {
                            "href": "http://127.0.0.1:5000/v3/",
                            "rel": "self"
                        }
                    ],
                    "media-types": [
                        {
                            "base": "application/json",
                            "type": "application/vnd.openstack.identity-v3+json"
                        }
                    ],
                    "status": "stable",
                    "updated": "2018-02-28T00:00:00Z"
                },
                {
                    "id": "v2.0",
                    "links": [
                        {
                            "href": "http://127.0.0.1:5000/v2.0/",
                            "rel": "self"
                        },
                        {
                            "href": "https://docs.openstack.org/",
                            "rel": "describedby",
                            "type": "text/html"
                        }
                    ],
                    "media-types": [
                        {
                            "base": "application/json",
                            "type": "application/vnd.openstack.identity-v2.0+json"
                        }
                    ],
                    "status": "deprecated",
                    "updated": "2016-08-04T00:00:00Z"
                }
            ]
        }
    }

Tokens
======

Default scope
-------------

Get a token with default scope (may be unscoped):

.. code-block:: bash

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    { "auth": {
        "identity": {
          "methods": ["password"],
          "password": {
            "user": {
              "name": "admin",
              "domain": { "id": "default" },
              "password": "adminpwd"
            }
          }
        }
      }
    }' \
      "http://localhost:5000/v3/auth/tokens" ; echo

Example response:

.. code-block:: bash

  HTTP/1.1 201 Created
  X-Subject-Token: MIIFvgY...
  Vary: X-Auth-Token
  Content-Type: application/json
  Content-Length: 1025
  Date: Tue, 10 Jun 2014 20:55:16 GMT

  {
    "token": {
      "methods": ["password"],
      "roles": [{
        "id": "9fe2ff9ee4384b1894a90878d3e92bab",
        "name": "_member_"
      }, {
        "id": "c703057be878458588961ce9a0ce686b",
        "name": "admin"
      }],
      "expires_at": "2014-06-10T2:55:16.806001Z",
      "project": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "8538a3f13f9541b28c2620eb19065e45",
        "name": "admin"
      },
      "catalog": [{
        "endpoints": [{
          "url": "http://localhost:3537/v2.0",
          "region": "RegionOne",
          "interface": "admin",
          "id": "29beb2f1567642eb810b042b6719ea88"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "internal",
          "id": "8707e3735d4415c97ae231b4841eb1c"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "public",
          "id": "ef303187fc8d41668f25199c298396a5"
        }],
        "type": "identity",
        "id": "bd73972c0e14fb69bae8ff76e112a90",
        "name": "keystone"
      }],
      "extras": {},
      "user": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "3ec3164f750146be97f21559ee4d9c51",
        "name": "admin"
      },
      "audit_ids": ["yRt0UrxJSs6-WYJgwEMMmg"],
      "issued_at": "201406-10T20:55:16.806027Z"
    }
  }


Project-scoped
--------------

Get a project-scoped token:

.. code-block:: bash

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    { "auth": {
        "identity": {
          "methods": ["password"],
          "password": {
            "user": {
              "name": "admin",
              "domain": { "id": "default" },
              "password": "adminpwd"
            }
          }
        },
        "scope": {
          "project": {
            "name": "demo",
            "domain": { "id": "default" }
          }
        }
      }
    }' \
      "http://localhost:5000/v3/auth/tokens" ; echo

Example response:

.. code-block:: bash

  HTTP/1.1 201 Created
  X-Subject-Token: MIIFfQ...
  Vary: X-Auth-Token
  Content-Type: application/json
  Content-Length: 960
  Date: Tue, 10 Jun 2014 20:40:14 GMT

  {
    "token": {
      "audit_ids": ["ECwrVNWbSCqmEgPnu0YCRw"],
      "methods": ["password"],
      "roles": [{
        "id": "c703057be878458588961ce9a0ce686b",
        "name": "admin"
      }],
      "expires_at": "2014-06-10T21:40:14.360795Z",
      "project": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "3d4c2c82bd5948f0bcab0cf3a7c9b48c",
        "name": "demo"
      },
      "catalog": [{
        "endpoints": [{
          "url": "http://localhost:35357/v2.0",
          "region": "RegionOne",
          "interface": "admin",
          "id": "29beb2f1567642eb810b042b6719ea88"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "internal",
          "id": "87057e3735d4415c97ae231b4841eb1c"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "public",
          "id": "ef303187fc8d41668f25199c298396a5"
        }],
        "type": "identity",
        "id": "bd7397d2c0e14fb69bae8ff76e112a90",
        "name": "keystone"
      }],
      "extras": {},
      "user": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "3ec3164f750146be97f21559ee4d9c51",
        "name": "admin"
      },
      "issued_at": "2014-06-10T20:40:14.360822Z"
    }
  }


Domain-Scoped
-------------

Get a domain-scoped token (Note that you're going to need a role-assignment on
the domain first!):

.. code-block:: bash

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    { "auth": {
        "identity": {
          "methods": ["password"],
          "password": {
            "user": {
              "name": "admin",
              "domain": { "id": "default" },
              "password": "adminpwd"
            }
          }
        },
        "scope": {
          "domain": {
            "id": "default"
          }
        }
      }
    }' \
      "http://localhost:5000/v3/auth/tokens" ; echo

Example response:

.. code-block:: bash

  HTTP/1.1 201 Created
  X-Subject-Token: MIIFNg...
  Vary: X-Auth-Token
  Content-Type: application/json
  Content-Length: 889
  Date: Tue, 10 Jun 2014 20:52:59 GMT

  {
    "token": {
      "domain": {
        "id": "default",
        "name": "Default"
      },
      "methods": ["password"],
      "roles": [{
        "id": "c703057be878458588961ce9a0ce686b",
        "name": "admin"
      }],
      "expires_at": "2014-06-10T21:52:58.852167Z",
      "catalog": [{
        "endpoints": [{
          "url": "http://localhost:35357/v2.0",
          "region": "RegionOne",
          "interface": "admin",
          "id": "29beb2f1567642eb810b042b6719ea88"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "internal",
          "id": "87057e3735d4415c97ae231b4841eb1c"
        }, {
          "url": "http://localhost:5000/v2.0",
          "region": "RegionOne",
          "interface": "public",
          "id": "ef303187fc8d41668f25199c298396a5"
        }],
        "type": "identity",
        "id": "bd7397d2c0e14fb69bae8ff76e112a90",
        "name": "keystone"
      }],
      "extras": {},
      "user": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "3ec3164f750146be97f21559ee4d9c51",
        "name": "admin"
      },
      "audit_ids": ["Xpa6Uyn-T9S6mTREudUH3w"],
      "issued_at": "2014-06-10T20:52:58.852194Z"
    }
  }


Getting a token from a token
----------------------------

Get a token from a token:

.. code-block:: bash

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    { "auth": {
        "identity": {
          "methods": ["token"],
          "token": {
            "id": "'$OS_TOKEN'"
          }
        }
      }
    }' \
      "http://localhost:5000/v3/auth/tokens" ; echo


Example response:

.. code-block:: bash

  HTTP/1.1 201 Created
  X-Subject-Token: MIIFxw...
  Vary: X-Auth-Token
  Content-Type: application/json
  Content-Length: 1034
  Date: Tue, 10 Jun 2014 21:00:05 GMT

  {
    "token": {
      "methods": ["token", "password"],
      "expires_at": "2015-05-28T07:43:44.808209Z",
      "extras": {},
      "user": {
        "domain": {
          "id": "default",
          "name": "Default"
        },
        "id": "753867c25c3340ffad1abc22d488c31a",
        "name": "admin"
      },
      "audit_ids": ["ZE0OPSuzTmCXHo0eIOYltw",
        "xxIQCkHOQOywL0oY6CTppQ"
      ],
      "issued_at": "2015-05-28T07:19:23.763532Z"
    }
  }

.. note::

    If a scope was included in the request body then this would get a token
    with the new scope.


DELETE /v3/auth/tokens
----------------------

Revoke a token:

.. code-block:: bash

    curl -i -X DELETE \
      -H "X-Auth-Token: $OS_TOKEN" \
      -H "X-Subject-Token: $OS_TOKEN" \
      "http://localhost:5000/v3/auth/tokens"

If there's no error then the response is empty.


Domains
=======

GET /v3/domains
---------------

List domains:

.. code-block:: bash

    curl -s \
      -H "X-Auth-Token: $OS_TOKEN" \
      "http://localhost:5000/v3/domains" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "domains": [
            {
                "description": "Owns users and tenants (i.e. projects) available on Identity API v2.",
                "enabled": true,
                "id": "default",
                "links": {
                    "self": "http://identity-server:5000/v3/domains/default"
                },
                "name": "Default"
            }
        ],
        "links": {
            "next": null,
            "previous": null,
            "self": "http://identity-server:5000/v3/domains"
        }
    }


POST /v3/domains
----------------

Create a domain:

.. code-block:: bash

    curl -s \
      -H "X-Auth-Token: $OS_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{ "domain": { "name": "newdomain"}}' \
      "http://localhost:5000/v3/domains" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "domain": {
            "enabled": true,
            "id": "3a5140aecd974bf08041328b53a62458",
            "links": {
                "self": "http://identity-server:5000/v3/domains/3a5140aecd974bf08041328b53a62458"
            },
            "name": "newdomain"
        }
    }


Projects
========

GET /v3/projects
----------------

List projects:

.. code-block:: bash

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     "http://localhost:5000/v3/projects" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "links": {
            "next": null,
            "previous": null,
            "self": "http://localhost:5000/v3/projects"
        },
        "projects": [
            {
                "description": null,
                "domain_id": "default",
                "enabled": true,
                "id": "3d4c2c82bd5948f0bcab0cf3a7c9b48c",
                "links": {
                    "self": "http://localhost:5000/v3/projects/3d4c2c82bd5948f0bcab0cf3a7c9b48c"
                },
                "name": "demo"
            }
        ]
    }


PATCH /v3/projects/{id}
-----------------------

Disable a project:

.. code-block:: bash

    curl -s -X PATCH \
      -H "X-Auth-Token: $OS_TOKEN" \
      -H "Content-Type: application/json" \
      -d '
    {
      "project": {
          "enabled": false
        }
    }'\
      "http://localhost:5000/v3/projects/$PROJECT_ID"  | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "project": {
            "description": null,
            "domain_id": "default",
            "enabled": false,
            "extra": {},
            "id": "3d4c2c82bd5948f0bcab0cf3a7c9b48c",
            "links": {
                "self": "http://localhost:5000/v3/projects/3d4c2c82bd5948f0bcab0cf3a7c9b48c"
            },
            "name": "demo"
        }
    }


GET /v3/services
================

List the services:

.. code-block:: bash

    curl -s \
      -H "X-Auth-Token: $OS_TOKEN" \
      "http://localhost:5000/v3/services" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "links": {
            "next": null,
            "previous": null,
            "self": "http://localhost:5000/v3/services"
        },
        "services": [
            {
                "description": "Keystone Identity Service",
                "enabled": true,
                "id": "bd7397d2c0e14fb69bae8ff76e112a90",
                "links": {
                    "self": "http://localhost:5000/v3/services/bd7397d2c0e14fb69bae8ff76e112a90"
                },
                "name": "keystone",
                "type": "identity"
            }
        ]
    }



GET /v3/endpoints
=================

List the endpoints:

.. code-block:: bash

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     "http://localhost:5000/v3/endpoints" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "endpoints": [
            {
                "enabled": true,
                "id": "29beb2f1567642eb810b042b6719ea88",
                "interface": "admin",
                "links": {
                    "self": "http://localhost:5000/v3/endpoints/29beb2f1567642eb810b042b6719ea88"
                },
                "region": "RegionOne",
                "service_id": "bd7397d2c0e14fb69bae8ff76e112a90",
                "url": "http://localhost:35357/v2.0"
            }
        ],
        "links": {
            "next": null,
            "previous": null,
            "self": "http://localhost:5000/v3/endpoints"
        }
    }


Users
=====

GET /v3/users
-------------

List users:

.. code-block:: bash

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     "http://localhost:5000/v3/users" | python -mjson.tool

POST /v3/users
--------------

Create a user:

.. code-block:: bash

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"user": {"name": "newuser", "password": "changeme"}}' \
     "http://localhost:5000/v3/users" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "user": {
            "domain_id": "default",
            "enabled": true,
            "id": "ec8fc20605354edd91873f2d66bf4fc4",
            "links": {
                "self": "http://identity-server:5000/v3/users/ec8fc20605354edd91873f2d66bf4fc4"
            },
            "name": "newuser"
        }
    }

GET /v3/users/{user_id}
-----------------------

Show details for a user:

.. code-block:: bash

    USER_ID=ec8fc20605354edd91873f2d66bf4fc4

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     "http://localhost:5000/v3/users/$USER_ID" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "user": {
            "domain_id": "default",
            "enabled": true,
            "id": "ec8fc20605354edd91873f2d66bf4fc4",
            "links": {
                "self": "http://localhost:5000/v3/users/ec8fc20605354edd91873f2d66bf4fc4"
            },
            "name": "newuser"
        }
    }

POST /v3/users/{user_id}/password
---------------------------------

Change password (using the default policy, this can be done as the user):

.. code-block:: bash

    USER_ID=b7793000f8d84c79af4e215e9da78654
    ORIG_PASS=userpwd
    NEW_PASS=newuserpwd

    curl \
     -H "X-Auth-Token: $OS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{ "user": {"password": "'$NEW_PASS'", "original_password": "'$ORIG_PASS'"} }' \
     "http://localhost:5000/v3/users/$USER_ID/password"

.. note::

    This command doesn't print anything if the request was successful.

PATCH /v3/users/{user_id}
-------------------------

Reset password (using the default policy, this requires admin):

.. code-block:: bash

    USER_ID=b7793000f8d84c79af4e215e9da78654
    NEW_PASS=newuserpwd

    curl -s -X PATCH \
     -H "X-Auth-Token: $OS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{ "user": {"password": "'$NEW_PASS'"} }' \
     "http://localhost:5000/v3/users/$USER_ID" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "user": {
            "default_project_id": "3d4c2c82bd5948f0bcab0cf3a7c9b48c",
            "domain_id": "default",
            "email": "demo@example.com",
            "enabled": true,
            "extra": {
                "email": "demo@example.com"
            },
            "id": "269348fdd9374b8885da1418e0730af1",
            "links": {
                "self": "http://localhost:5000/v3/users/269348fdd9374b8885da1418e0730af1"
            },
            "name": "demo"
        }
    }


PUT /v3/projects/{project_id}/groups/{group_id}/roles/{role_id}
===============================================================

Create group role assignment on project:

.. code-block:: bash

    curl -s -X PUT \
     -H "X-Auth-Token: $OS_TOKEN" \
     "http://localhost:5000/v3/projects/$PROJECT_ID/groups/$GROUP_ID/roles/$ROLE_ID" |
       python -mjson.tool

There's no data in the response if the operation is successful.


POST /v3/OS-TRUST/trusts
========================

Create a trust:

.. code-block:: bash

    curl -s \
     -H "X-Auth-Token: $OS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '
    { "trust": {
        "expires_at": "2014-12-30T23:59:59.999999Z",
        "impersonation": false,
        "project_id": "'$PROJECT_ID'",
        "roles": [
            { "name": "admin" }
          ],
        "trustee_user_id": "'$DEMO_USER_ID'",
        "trustor_user_id": "'$ADMIN_USER_ID'"
    }}'\
     "http://localhost:5000/v3/OS-TRUST/trusts" | python -mjson.tool

Example response:

.. code-block:: javascript

    {
        "trust": {
            "expires_at": "2014-12-30T23:59:59.999999Z",
            "id": "394998fa61f14736b1f0c1f322882949",
            "impersonation": false,
            "links": {
                "self": "http://localhost:5000/v3/OS-TRUST/trusts/394998fa61f14736b1f0c1f322882949"
            },
            "project_id": "3d4c2c82bd5948f0bcab0cf3a7c9b48c",
            "remaining_uses": null,
            "roles": [
                {
                    "id": "c703057be878458588961ce9a0ce686b",
                    "links": {
                        "self": "http://localhost:5000/v3/roles/c703057be878458588961ce9a0ce686b"
                    },
                    "name": "admin"
                }
            ],
            "roles_links": {
                "next": null,
                "previous": null,
                "self": "http://localhost:5000/v3/OS-TRUST/trusts/394998fa61f14736b1f0c1f322882949/roles"
            },
            "trustee_user_id": "269348fdd9374b8885da1418e0730af1",
            "trustor_user_id": "3ec3164f750146be97f21559ee4d9c51"
        }
    }
