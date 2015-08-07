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
    driver = sql

2. Add the ``oauth1`` authentication method to the ``[auth]`` section in ``keystone.conf``::

    [auth]
    methods = external,password,token,oauth1

3. Add the ``oauth1_extension`` filter to the ``api_v3`` pipeline in
   ``keystone-paste.ini``. This must be added after ``json_body`` and before
   the last entry in the pipeline. For example::

    [pipeline:api_v3]
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth json_body ec2_extension_v3 s3_extension simple_cert_extension revoke_extension oauth1_extension service_v3

4. Create the OAuth1 extension tables if using the provided SQL backend. For example::

    ./bin/keystone-manage db_sync --extension oauth1

5. Optionally, if deploying under an HTTPD server (i.e. Apache), set the
   `WSGIPassAuthorization` to allow the OAuth Authorization headers to
   pass through `mod_wsgi`. For example, add the following to the Keystone
   virtual host file::

    WSGIPassAuthorization On
