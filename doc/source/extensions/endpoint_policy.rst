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

======================================
Enabling the Endpoint Policy Extension
======================================

To enable the endpoint policy extension:

1. Optionally, add the endpoint policy extension driver to the
   ``[endpoint_policy]`` section in ``keystone.conf``. For example::

    [endpoint_policy]
    driver = sql

2. Add the ``endpoint_policy_extension`` policy to the ``api_v3`` pipeline in
   ``keystone-paste.ini``. This must be added after ``json_body`` and before
   the last entry in the pipeline. For example::

    [pipeline:api_v3]
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth json_body ec2_extension_v3 s3_extension simple_cert_extension revoke_extension service_v3 endpoint_policy_extension service_v3

3. Create the endpoint policy extension tables if using the provided SQL backend. For example::

    ./bin/keystone-manage db_sync --extension endpoint_policy
