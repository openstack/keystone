..
      Copyright 2011 OpenStack, LLC
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

===============================
Service API Examples Using Curl
===============================

The service API is defined to be a subset of the Admin API and, by
default, runs on port 5000.

GET /
=====

This call is identical to that documented for the Admin API, except
that it uses port 5000, instead of port 35357, by default::

    $ curl http://0.0.0.0:5000

or::

    $ curl http://0.0.0.0:5000/v2.0/

See the `Admin API Examples Using Curl`_ for more info.

.. _`Admin API Examples Using Curl`: adminAPI_curl_examples.html

GET /extensions
===============

This call is identical to that documented for the Admin API.

POST /tokens
============

This call is identical to that documented for the Admin API.

GET /tenants
============

List all of the tenants your token can access::

    $ curl -H "X-Auth-Token:887665443383838" http://localhost:5000/v2.0/tenants

Returns::

    {
        "tenants_links": [],
        "tenants": [
            {
                "enabled": true,
                "description": "None",
                "name": "customer-x",
                "id": "1"
            }
        ]
    }
