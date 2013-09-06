# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from keystone.common import wsgi


class Router(wsgi.ComposableRouter):
    def __init__(self, controller, collection_key, key):
        self.controller = controller
        self.key = key
        self.collection_key = collection_key

    def add_routes(self, mapper):
        collection_path = '/%(collection_key)s' % {
            'collection_key': self.collection_key}
        entity_path = '/%(collection_key)s/{%(key)s_id}' % {
            'collection_key': self.collection_key,
            'key': self.key}

        mapper.connect(
            collection_path,
            controller=self.controller,
            action='create_%s' % self.key,
            conditions=dict(method=['POST']))
        mapper.connect(
            collection_path,
            controller=self.controller,
            action='list_%s' % self.collection_key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=self.controller,
            action='get_%s' % self.key,
            conditions=dict(method=['GET']))
        mapper.connect(
            entity_path,
            controller=self.controller,
            action='update_%s' % self.key,
            conditions=dict(method=['PATCH']))
        mapper.connect(
            entity_path,
            controller=self.controller,
            action='delete_%s' % self.key,
            conditions=dict(method=['DELETE']))
