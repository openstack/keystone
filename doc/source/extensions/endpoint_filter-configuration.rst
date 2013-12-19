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

==================================
Enabling Endpoint Filter Extension
==================================

To enable the endpoint filter extension:

1. add the endpoint filter extension catalog driver to the ``[catalog]`` section
   in ``keystone.conf``. example::

    [catalog]
    driver = keystone.contrib.endpoint_filter.backends.catalog_sql.EndpointFilterCatalog

2. add the ``endpoint_filter_extension`` filter to the ``api_v3`` pipeline in
   ``keystone-paste.ini``. example::

    [pipeline:api_v3]
    pipeline = access_log sizelimit url_normalize token_auth admin_token_auth xml_body json_body ec2_extension s3_extension endpoint_filter_extension service_v3

3. create the endpoint filter extension tables if using the provided sql backend. example::
    ./bin/keystone-manage db_sync --extension endpoint_filter

4. optional: change ``return_all_endpoints_if_no_filter`` the ``[endpoint_filter]`` section
   in ``keystone.conf`` to return an empty catalog if no associations are made. example::

    [endpoint_filter]
    return_all_endpoints_if_no_filter = False