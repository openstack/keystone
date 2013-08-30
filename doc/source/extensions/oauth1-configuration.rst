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

=============================
Enabling the OAuth1 Extension
=============================

To enable the OAuth1 extension:

1. Optionally, add the oauth1 extension driver to the ``[oauth1]`` section in ``keystone.conf``. For example::

    [oauth1]
    driver = keystone.contrib.oauth1.backends.sql.OAuth1

2. Add the ``oauth1_extension`` filter to the ``api_v3`` pipeline in ``keystone-paste.ini``. For example::

    [pipeline:api_v3]
    pipeline = access_log sizelimit url_normalize token_auth admin_token_auth xml_body json_body ec2_extension s3_extension oauth1_extension service_v3

3. Create the OAuth1 extension tables if using the provided SQL backend. For example::

    ./bin/keystone-manage db_sync --extension oauth1
