..
      Copyright 2011-2013 OpenStack, Foundation
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

======================================
Enabling the Endpoint Filter Extension
======================================

To enable the endpoint filter extension:

1. Add the endpoint filter extension catalog driver to the ``[catalog]`` section
   in ``keystone.conf``. For example::

    [catalog]
    driver = catalog_sql

2. Add the ``endpoint_filter_extension`` filter to the ``api_v3`` pipeline in
   ``keystone-paste.ini``. This must be added after ``json_body`` and before
   the last entry in the pipeline. For example::

    [pipeline:api_v3]
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth json_body ec2_extension_v3 s3_extension simple_cert_extension revoke_extension endpoint_filter_extension service_v3

3. Create the endpoint filter extension tables if using the provided sql backend. For example::

    ./bin/keystone-manage db_sync --extension endpoint_filter

4. Optionally, change ``return_all_endpoints_if_no_filter`` the ``[endpoint_filter]`` section
   in ``keystone.conf`` to return an empty catalog if no associations are made. For example::

    [endpoint_filter]
    return_all_endpoints_if_no_filter = False
