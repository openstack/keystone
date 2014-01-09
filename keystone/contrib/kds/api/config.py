# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

# Server Specific Configurations
server = {
    'port': 9109,
    'host': '0.0.0.0'
}

# Pecan Application Configurations
app = {
    'root': 'keystone.contrib.kds.api.root.RootController',
    'modules': ['keystone.contrib.kds.api'],
    'static_root': '%(confdir)s/public',
    'template_path': '%(confdir)s/templates',
    'debug': False,
}

# Custom Configurations must be in Python dictionary format::
#
# foo = {'bar': 'baz'}
