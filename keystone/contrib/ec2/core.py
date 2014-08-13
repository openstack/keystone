# Copyright 2012 OpenStack Foundation
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

from keystone.common import extension


EXTENSION_DATA = {
    'name': 'OpenStack EC2 API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-EC2/v1.0',
    'alias': 'OS-EC2',
    'updated': '2013-07-07T12:00:0-00:00',
    'description': 'OpenStack EC2 Credentials backend.',
    'links': [
        {
            'rel': 'describedby',
            # TODO(ayoung): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
