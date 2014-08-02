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
"""
The only types of routers in this file should be ``ComposingRouters``.

The routers for the backends should be in the backend-specific router modules.
For example, the ``ComposableRouter`` for ``identity`` belongs in::

    keystone.identity.routers

"""


from keystone.common import wsgi
from keystone import controllers


class Extension(wsgi.ComposableRouter):
    def __init__(self, is_admin=True):
        if is_admin:
            self.controller = controllers.AdminExtensions()
        else:
            self.controller = controllers.PublicExtensions()

    def add_routes(self, mapper):
        extensions_controller = self.controller
        mapper.connect('/extensions',
                       controller=extensions_controller,
                       action='get_extensions_info',
                       conditions=dict(method=['GET']))
        mapper.connect('/extensions/{extension_alias}',
                       controller=extensions_controller,
                       action='get_extension_info',
                       conditions=dict(method=['GET']))


class VersionV2(wsgi.ComposableRouter):
    def __init__(self, description):
        self.description = description

    def add_routes(self, mapper):
        version_controller = controllers.Version(self.description)
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_v2')


class VersionV3(wsgi.ComposableRouter):
    def __init__(self, description, routers):
        self.description = description
        self._routers = routers

    def add_routes(self, mapper):
        version_controller = controllers.Version(self.description,
                                                 routers=self._routers)
        mapper.connect('/',
                       controller=version_controller,
                       action='get_version_v3')


class Versions(wsgi.ComposableRouter):
    def __init__(self, description):
        self.description = description

    def add_routes(self, mapper):
        version_controller = controllers.Version(self.description)
        mapper.connect('/',
                       controller=version_controller,
                       action='get_versions')
