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

Unscoped
--------

Get an unscoped token:

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
  Content-Length: 312
  Date: Fri, 11 May 2018 03:15:01 GMT

  {
    "token": {
        "issued_at": "2018-05-11T03:15:01.000000Z",
        "audit_ids": [
            "0PKh_BDKTWqqaFONE-Sxbg"
        ],
        "methods": [
            "password"
        ],
        "expires_at": "2018-05-11T04:15:01.000000Z",
        "user": {
            "password_expires_at": null,
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "9a7e43333cc44ef4b988f05fc3d3a49d",
            "name": "admin"
        }
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
            "name": "admin",
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
  Content-Length: 3518
  Date: Fri, 11 May 2018 03:38:39 GMT

  {
    "token": {
        "is_domain": false,
        "methods": [
            "password"
        ],
        "roles": [
            {
                "id": "b57680c826b44b5ca6122d0f792c3184",
                "name": "Member"
            },
            {
                "id": "3a7bd258345f47479a26aea11a6cc2bb",
                "name": "admin"
            }
        ],
        "expires_at": "2018-05-11T04:38:39.000000Z",
        "project": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "3a705b9f56bb439381b43c4fe59dccce",
            "name": "admin"
        },
        "catalog": [
            {
                "endpoints": [
                    {
                        "url": "http://localhost/identity",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "30a91932e4e94a8ca4dc145bb1bb6b4b"
                    },
                    {
                        "url": "http://localhost/identity",
                        "interface": "admin",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "94d4768735104c9091f0468e7d31c189"
                    }
                ],
                "type": "identity",
                "id": "09af9253500b41ef976a07322b2fa388",
                "name": "keystone"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/volume/v2/3a705b9f56bb439381b43c4fe59dccce",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "1c4ffe935e7643d99b55938cb12bc38d"
                    }
                ],
                "type": "volumev2",
                "id": "413a44234e1a4c3781d4a3c7a7e4c895",
                "name": "cinderv2"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/image",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "33237fdd1a744d0fb40f9127f21ddad4"
                    }
                ],
                "type": "image",
                "id": "4d473252145546d2aa589605f1e177c7",
                "name": "glance"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/placement",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "1a421e2f97684d3f86ab4d2cc9c86362"
                    }
                ],
                "type": "placement",
                "id": "5dcecbdd4a1d44d0855c560301b27bb5",
                "name": "placement"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/compute/v2.1",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "8e7ea663cc41477c9629cc710bbb1c7d"
                    }
                ],
                "type": "compute",
                "id": "87d49efa8fb64006bdb123d223ddcae2",
                "name": "nova"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/volume/v1/3a705b9f56bb439381b43c4fe59dccce",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "97a2c0ac7e304316a1eb58a3757e6ef8"
                    }
                ],
                "type": "volume",
                "id": "9408080f1970482aa0e38bc2d4ea34b7",
                "name": "cinder"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost:8080/v1/AUTH_3a705b9f56bb439381b43c4fe59dccce",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "d0d823615b0747a9aeca8b83fba105f0"
                    },
                    {
                        "url": "http://localhost:8080",
                        "interface": "admin",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "e4cb86d9232349f091e0a02390deeb79"
                    }
                ],
                "type": "object-store",
                "id": "957ba1fe8b0443f0afe64bfd0858ba5e",
                "name": "swift"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost:9696/",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "aa4a0e61cdc54372967ee9e2298f1d53"
                    }
                ],
                "type": "network",
                "id": "960fbc66bfcb4fa7900023f647fdc3a5",
                "name": "neutron"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/volume/v3/3a705b9f56bb439381b43c4fe59dccce",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "0c38045a91c34d798e0d2008fee7521d"
                    }
                ],
                "type": "volumev3",
                "id": "98adb083914f423d9cb74ad5527e37cb",
                "name": "cinderv3"
            },
            {
                "endpoints": [
                    {
                        "url": "http://localhost/compute/v2/3a705b9f56bb439381b43c4fe59dccce",
                        "interface": "public",
                        "region": "RegionOne",
                        "region_id": "RegionOne",
                        "id": "562e12b9ee9549e8b857218ccf2ae321"
                    }
                ],
                "type": "compute_legacy",
                "id": "a31e688016614430b28cddddf12d7b88",
                "name": "nova_legacy"
            }
        ],
        "user": {
            "password_expires_at": null,
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "9a7e43333cc44ef4b988f05fc3d3a49d",
            "name": "admin"
        },
        "audit_ids": [
            "TbdrnW4MQDq_GPAVN9-JOQ"
        ],
        "issued_at": "2018-05-11T03:38:39.000000Z"
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
  Content-Length: 2590
  Date: Fri, 11 May 2018 03:37:09 GMT

  {
    "token": {
        "domain": {
            "id": "default",
            "name": "Default"
        },
        "methods": [
            "password"
        ],
        "roles": [
            {
                "id": "b57680c826b44b5ca6122d0f792c3184",
                "name": "Member"
            },
            {
                "id": "3a7bd258345f47479a26aea11a6cc2bb",
                "name": "admin"
            }
        ],
        "expires_at": "2018-05-11T04:37:09.000000Z",
        "catalog": [
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost/identity",
                        "region": "RegionOne",
                        "interface": "public",
                        "id": "30a91932e4e94a8ca4dc145bb1bb6b4b"
                    },
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost/identity",
                        "region": "RegionOne",
                        "interface": "admin",
                        "id": "94d4768735104c9091f0468e7d31c189"
                    }
                ],
                "type": "identity",
                "id": "09af9253500b41ef976a07322b2fa388",
                "name": "keystone"
            },
            {
                "endpoints": [],
                "type": "volumev2",
                "id": "413a44234e1a4c3781d4a3c7a7e4c895",
                "name": "cinderv2"
            },
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost/image",
                        "region": "RegionOne",
                        "interface": "public",
                        "id": "33237fdd1a744d0fb40f9127f21ddad4"
                    }
                ],
                "type": "image",
                "id": "4d473252145546d2aa589605f1e177c7",
                "name": "glance"
            },
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost/placement",
                        "region": "RegionOne",
                        "interface": "public",
                        "id": "1a421e2f97684d3f86ab4d2cc9c86362"
                    }
                ],
                "type": "placement",
                "id": "5dcecbdd4a1d44d0855c560301b27bb5",
                "name": "placement"
            },
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost/compute/v2.1",
                        "region": "RegionOne",
                        "interface": "public",
                        "id": "8e7ea663cc41477c9629cc710bbb1c7d"
                    }
                ],
                "type": "compute",
                "id": "87d49efa8fb64006bdb123d223ddcae2",
                "name": "nova"
            },
            {
                "endpoints": [],
                "type": "volume",
                "id": "9408080f1970482aa0e38bc2d4ea34b7",
                "name": "cinder"
            },
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost:8080",
                        "region": "RegionOne",
                        "interface": "admin",
                        "id": "e4cb86d9232349f091e0a02390deeb79"
                    }
                ],
                "type": "object-store",
                "id": "957ba1fe8b0443f0afe64bfd0858ba5e",
                "name": "swift"
            },
            {
                "endpoints": [
                    {
                        "region_id": "RegionOne",
                        "url": "http://localhost:9696/",
                        "region": "RegionOne",
                        "interface": "public",
                        "id": "aa4a0e61cdc54372967ee9e2298f1d53"
                    }
                ],
                "type": "network",
                "id": "960fbc66bfcb4fa7900023f647fdc3a5",
                "name": "neutron"
            },
            {
                "endpoints": [],
                "type": "volumev3",
                "id": "98adb083914f423d9cb74ad5527e37cb",
                "name": "cinderv3"
            },
            {
                "endpoints": [],
                "type": "compute_legacy",
                "id": "a31e688016614430b28cddddf12d7b88",
                "name": "nova_legacy"
            }
        ],
        "user": {
            "password_expires_at": null,
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "9a7e43333cc44ef4b988f05fc3d3a49d",
            "name": "admin"
        },
        "audit_ids": [
            "Sfc8_kywQx-tWNkEVqA1Iw"
        ],
        "issued_at": "2018-05-11T03:37:09.000000Z"
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
  Content-Length: 347
  Date: Fri, 11 May 2018 03:41:29 GMT

  {
    "token": {
        "issued_at": "2018-05-11T03:41:29.000000Z",
        "audit_ids": [
            "zS_C_KROTFeZm-VlG1LjbA",
            "RAjE82q8Rz-Cd50ogCpx3Q"
        ],
        "methods": [
            "token",
            "password"
        ],
        "expires_at": "2018-05-11T04:40:00.000000Z",
        "user": {
            "password_expires_at": null,
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "9a7e43333cc44ef4b988f05fc3d3a49d",
            "name": "admin"
        }
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
