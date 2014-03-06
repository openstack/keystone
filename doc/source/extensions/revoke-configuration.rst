    ..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

================================
Enabling the OS-REVOKE Extension
================================

.. WARNING::

    The ``OS-REVOKE`` Extension is considered experimental in Icehouse and will
    continue to see improvement over the next development cycle.

To enable the ``OS-REVOKE`` extension:

1. Add the driver fields and values in the ``[revoke]`` section
   in ``keystone.conf``.  For the KVS Driver::

    [revoke]
    driver = keystone.contrib.revoke.backends.kvs.Revoke

For the SQL driver::

    driver = keystone.contrib.revoke.backends.sql.Revoke


2. Add the required ``filter`` to the ``pipeline`` in ``keystone-paste.ini``::

    [filter:revoke_extension]
    paste.filter_factory = keystone.contrib.revoke.routers:RevokeExtension.factory

    [pipeline:api_v3]
    pipeline = access_log sizelimit url_normalize token_auth admin_token_auth xml_body json_body revoke_extension service_v3

3. Create the extension tables if using the provided SQL backend::

    ./bin/keystone-manage db_sync --extension revoke
