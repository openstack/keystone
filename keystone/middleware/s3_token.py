# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""
S3 TOKEN MIDDLEWARE

The S3 Token middleware is deprecated as of IceHouse. It's been moved into
python-keystoneclient, `keystoneclient.middleware.s3_token`.

This WSGI component:

* Get a request from the swift3 middleware with an S3 Authorization
  access key.
* Validate s3 token in Keystone.
* Transform the account name to AUTH_%(tenant_name).

"""

from keystoneclient.middleware import s3_token

from keystone.openstack.common import versionutils


PROTOCOL_NAME = s3_token.PROTOCOL_NAME
split_path = s3_token.split_path
ServiceError = s3_token.ServiceError
filter_factory = s3_token.filter_factory


class S3Token(s3_token.S3Token):

    @versionutils.deprecated(
        versionutils.deprecated.ICEHOUSE,
        in_favor_of='keystoneclient.middleware.s3_token',
        remove_in=+1,
        what='keystone.middleware.s3_token')
    def __init__(self, app, conf):
        super(S3Token, self).__init__(app, conf)
