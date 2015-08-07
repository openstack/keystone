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

=================================
Enabling the Revocation Extension
=================================

.. NOTE::

    As of the Juno release, the example configuration files will have the
    ``OS-REVOKE`` extension enabled by default, thus it is not necessary to
    perform steps 1 and 2.
    Also, for new installations, the revocation extension tables are already
    migrated, thus it is not necessary to perform steps 3.

1. Optionally, add the revoke extension driver to the ``[revoke]`` section
   in ``keystone.conf``. For example::

    [revoke]
    driver = sql

2. Add the required ``filter`` to the ``pipeline`` in ``keystone-paste.ini``.
   This must be added after ``json_body`` and before the last entry in the
   pipeline. For example::

    [filter:revoke_extension]
    paste.filter_factory = keystone.contrib.revoke.routers:RevokeExtension.factory

    [pipeline:api_v3]
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth json_body ec2_extension_v3 s3_extension simple_cert_extension revoke_extension service_v3

3. Create the revocation extension tables if using the provided SQL backend.
   For example::

    ./bin/keystone-manage db_sync --extension revoke
