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

# package import
from sqlalchemy.orm import joinedload, aliased, sessionmaker

import ast

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from keystone import utils
from keystone.backends.sqlalchemy import models
import keystone.backends.api as top_api
import keystone.backends.models as top_models


_DRIVER = None

# TODO(dolph): these should be computed dynamically
MODEL_PREFIX = 'keystone.backends.sqlalchemy.models.'
API_PREFIX = 'keystone.backends.sqlalchemy.api.'


class Driver():
    def __init__(self, options):
        self.session = None
        self._engine = None
        connection_str = options['sql_connection']
        model_list = ast.literal_eval(options["backend_entities"])

        self._init_engine(connection_str)
        self._init_models(model_list)
        self._init_session_maker()

    def _init_engine(self, connection_str):
        if connection_str == "sqlite://":
            # in-memory sqlite
            self._engine = create_engine(
                connection_str,
                connect_args={'check_same_thread': False},
                poolclass=StaticPool)
        else:
            self._engine = create_engine(
                connection_str,
                pool_recycle=3600)

    def _init_models(self, model_list):
        tables = []

        for model in model_list:
            module = utils.import_module(MODEL_PREFIX + model)
            tables.append(module.__table__)

            top_models.set_value(model, module)

            if module.__api__ is not None:
                api_module = utils.import_module(API_PREFIX + module.__api__)
                top_api.set_value(module.__api__, api_module.get())

        tables_to_create = []
        for table in reversed(models.Base.metadata.sorted_tables):
            if table in tables:
                tables_to_create.append(table)

        models.Base.metadata.create_all(self._engine, tables=tables_to_create,
                                        checkfirst=True)

    def _init_session_maker(self):
        self.session = sessionmaker(
            bind=self._engine,
            autocommit=True,
            expire_on_commit=False)

    def get_session(self):
        """Creates a pre-configured database session"""
        return self.session()

    def reset(self):
        """Unregister models and reset DB engine.

        Useful clearing out data before testing

        TODO(dolph)::

            ... but what does this *do*? Issue DROP TABLE statements?
            TRUNCATE TABLE? Or is the scope of impact limited to python?
        """
        if self._engine is not None:
            models.Base.metadata.drop_all(self._engine)
            self._engine = None


def configure_backend(options):
    global _DRIVER
    _DRIVER = Driver(options)


def get_session():
    global _DRIVER
    return _DRIVER.get_session()


def unregister_models():
    global _DRIVER
    if _DRIVER:
        return _DRIVER.reset()
