# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
Starting point for routing EC2 requests.

The EC2 Token Middleware has been deprecated as of Juno. It has been moved into
keystonemiddleware, `keystonemiddleware.ec2_token`.

"""

from keystonemiddleware import ec2_token

from keystone.openstack.common import versionutils


class EC2Token(ec2_token.EC2Token):

    @versionutils.deprecated(
        versionutils.deprecated.JUNO,
        in_favor_of='keystonemiddleware.ec2_token.EC2Token',
        remove_in=+2,
        what='keystone.middleware.ec2_token.EC2Token')
    def __init__(self, *args, **kwargs):
        super(EC2Token, self).__init__(*args, **kwargs)


filter_factory = ec2_token.filter_factory
app_factory = ec2_token.app_factory
keystone_ec2_opts = ec2_token.keystone_ec2_opts
