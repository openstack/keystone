#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from keystone.server.flask import core as flask_core


# NOTE(morgan): While "_get_config_files" is present in the keystone_flask
# module, since it is considered "private", we are going to directly
# import core and call it directly, eventually keystone_flask will not
# export all the symbols from keystone.flask.core only specific ones that
# are meant for public consumption
def initialize_public_application():
    return flask_core.initialize_application(
        name='public', config_files=flask_core._get_config_files())


# Keystone does not differentiate between "admin" and public with the removal
# of V2.0
initialize_admin_application = initialize_public_application
