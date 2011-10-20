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

Curl Admin API examples
=======================

All examples assume default port usage (35357) and use the example admin account created
on the Getting Started page.

Initial GET
###########

Retrieves version, full API url, pdf doc link, and wadl link::

    $ curl http://0.0.0.0:35357

or::

    $ curl http://0.0.0.0:35357/v2.0/


Retrieve token
##############

Retrieves the token and expiration date for a user::

    $ curl -d '{"passwordCredentials":{"username": "MyAdmin", "password": "P@ssw0rd"}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens

This will return something like::

    {"auth": {"token": {"expires": "2011-08-10T17:45:22.838440", "id": "0eed0ced-4667-4221-a0b2-24c91f242b0b"}}}

.. note::

    Take note of the value ['auth']['token']['id'] value here, as you'll be using it in the calls below.

Retrieve a list of tenants
##########################

Run::

    $ curl -H "X-Auth-Token:999888777666" http://localhost:35357/v2.0/tenants

This will return something like::

    {"tenants": {"values": [{"enabled": 1, "id": "145", "name": "MyTenant", "description": null}], "links": []}}

Retrieve a list of users
########################

Run::

    $ curl -H "X-Auth-Token:999888777666" http://localhost:35357/v2.0/users

This will return something like::

    {"users": {"values": [{"email": null, "enabled": true, "id": "1227", "name": "MyAdmin", "tenantId": "MyTenant"}], "links": []}}

Retrieve information about the token
####################################

Run::

    $ curl -H "X-Auth-Token:999888777666" http://localhost:35357/v2.0/tokens/0eed0ced-4667-4221-a0b2-24c91f242b0b

This will return something like::

    {"auth": {"token": {"expires": "2011-08-11T04:26:58.145171", "id": "0eed0ced-4667-4221-a0b2-24c91f242b0b"}, "user": {"username": "MyAdmin", "roles": [{"roleId": "Admin", "id": 1}], "tenant": {"id": 932, "name": "MyTenant"}}}}   

Revoking a token
################

Run::

    $ curl -X DELETE -H "X-Auth-Token:999888777666" http://localhost:35357/tokens/0eed0ced-4667-4221-a0b2-24c91f242b0b

Creating a tenant
#################

Run::

    $ curl -H "X-Auth-Token:999888777666" -H "Content-type: application/json" -d '{"tenant":{"id": 416, "name":"MyTenant2", "description":"My 2nd Tenant", "enabled":true}}'  http://localhost:35357/tenants

This will return something like::

    {"tenant": {"enabled": true, "id": "MyTenant2", "description": "My 2nd Tenant"}}

Verifying the tenant
####################

Run::

    $ curl -H "X-Auth-Token:999888777666" http://localhost:35357/v2.0/tenants/MyTenant2

This will return something like::

    {"tenant": {"enabled": 1, "id": "MyTenant2", "description": "My 2nd Tenant"}}

Updating the tenant
###################

Run::

    $ curl -X PUT -H "X-Auth-Token:999888777666" -H "Content-type: application/json" -d '{"tenant":{"description":"My NEW 2nd Tenant"}}' http://localhost:35357/v2.0/tenants/MyTenant2

This will return something like::

    {"tenant": {"enabled": true, "id": "MyTenant2", "description": "My NEW 2nd Tenant"}}       

Deleting the tenant
###################

Run::

    $> curl -X DELETE -H "X-Auth-Token:999888777666" http://localhost:35357/v2.0/tenants/MyTenant2
