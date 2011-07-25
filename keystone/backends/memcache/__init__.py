# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
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

import ast
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import joinedload, aliased, sessionmaker

from keystone.common import config
from keystone.backends.alterdb import models
import keystone.utils as utils
import keystone.backends.api as top_api
import keystone.backends.models as top_models
import memcache

MODEL_PREFIX = 'keystone.backends.memcache.models.'
API_PREFIX = 'keystone.backends.memcache.api.'
memcache_server = None


def configure_backend(options):
    hosts = options['memcache_hosts']
    global memcache_server
    if not memcache_server:
        memcache_server = Memcache_Server(hosts)
    register_models(options)


class Memcache_Server():
    def __init__(self, hosts):
        self.hosts = hosts
        self.server = memcache.Client([self.hosts])

    def set(self, key, value, expiry=900):
        """
        This method is used to set a new value
        in the memcache server.
        """
        self.server.set(key.encode('utf-8'), value, expiry)

    def get(self, key):
        """
        This method is used to retrieve a value
        from the memcache server
        """
        return self.server.get(key.encode('utf-8'))

    def delete(self, key):
        """
        This method is used to delete a value from the
        memcached server. Lazy delete
        """
        self.server.delete(key.encode('utf-8'))


def register_models(options):
    """Register Models and create properties"""
    supported_memcache_models = ast.literal_eval(
                    options["backend_entities"])
    for supported_memcache_model in supported_memcache_models:
        model = utils.import_module(MODEL_PREFIX + supported_memcache_model)
        top_models.set_value(supported_memcache_model, model)
        if model.__api__ != None:
            model_api = utils.import_module(API_PREFIX + model.__api__)
            top_api.set_value(model.__api__, model_api.get())
