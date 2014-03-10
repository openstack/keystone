..
      Copyright 2014 OpenStack, Foundation
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

==============================
Enabling Federation Extension
==============================

To enable the federation extension:

1. Add the federation extension driver to the ``[federation]`` section in
   ``keystone.conf``. For example::

       [federation]
       driver = keystone.contrib.federation.backends.sql.Federation

2. Add the ``saml2`` authentication method to the ``[auth]`` section in
   ``keystone.conf``::

       [auth]
       methods = external,password,token,saml2
       saml2 = keystone.auth.plugins.saml2.Saml2

3. Add the ``federation_extension`` middleware to the ``api_v3`` pipeline in
   ``keystone-paste.ini``. For example::

       [pipeline:api_v3]
       pipeline = access_log sizelimit url_normalize token_auth admin_token_auth
       xml_body json_body ec2_extension s3_extension federation_extension
       service_v3

4. Create the federation extension tables if using the provided SQL backend.
   For example::

       ./bin/keystone-manage db_sync --extension federation
