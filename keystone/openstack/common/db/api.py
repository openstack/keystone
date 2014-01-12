# Copyright (c) 2013 Rackspace Hosting
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

"""Multiple DB API backend support.

Supported configuration options:

The following two parameters are in the 'database' group:
`backend`: DB backend name or full module path to DB backend module.

A DB backend module should implement a method named 'get_backend' which
takes no arguments.  The method can return any object that implements DB
API methods.
"""

from oslo.config import cfg

from keystone.openstack.common import importutils


db_opts = [
    cfg.StrOpt('backend',
               default='sqlalchemy',
               deprecated_name='db_backend',
               deprecated_group='DEFAULT',
               help='The backend to use for db'),
]

CONF = cfg.CONF
CONF.register_opts(db_opts, 'database')


class DBAPI(object):
    def __init__(self, backend_mapping=None):
        if backend_mapping is None:
            backend_mapping = {}
        backend_name = CONF.database.backend
        # Import the untranslated name if we don't have a
        # mapping.
        backend_path = backend_mapping.get(backend_name, backend_name)
        backend_mod = importutils.import_module(backend_path)
        self.__backend = backend_mod.get_backend()

    def __getattr__(self, key):
        return getattr(self.__backend, key)
