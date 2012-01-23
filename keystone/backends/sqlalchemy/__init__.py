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

# pylint: disable=W0602,W0603

from sqlalchemy.orm import joinedload, aliased, sessionmaker

import ast
import logging
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

try:
    # pylint: disable=E0611
    from migrate.versioning import exceptions as versioning_exceptions
except ImportError:
    from migrate import exceptions as versioning_exceptions

from keystone import utils
from keystone.backends.sqlalchemy import models
from keystone.backends.sqlalchemy import migration
import keystone.backends.api as top_api
import keystone.backends.models as top_models

logger = logging.getLogger(__name__)  # pylint: disable=C0103

_DRIVER = None


class Driver():
    def __init__(self, conf):
        self.session = None
        self._engine = None
        self.connection_str = conf.sql_connection
        model_list = ast.literal_eval(conf.backend_entities)
        self._init_engine(model_list)
        self._init_models(model_list)
        self._init_session_maker()

    def _init_engine(self, model_list):
        logger.info("Initializing sqlalchemy backend: %s" % \
                    self.connection_str)
        if self.connection_str == "sqlite://":
            # initialize in-memory sqlite (i.e. for testing)
            self._engine = create_engine(
                self.connection_str,
                connect_args={'check_same_thread': False},
                poolclass=StaticPool)

            # TODO(dolph): we should be using version control, but
            # we don't have a way to pass our in-memory instance to
            # the versioning api
            self._init_tables(model_list)
        else:
            # initialize a "real" database
            self._engine = create_engine(
                self.connection_str,
                pool_recycle=3600)
            self._init_version_control()
            self._init_tables(model_list)

    def _init_version_control(self):
        """Verify the state of the database"""
        repo_path = migration.get_migrate_repo_path()

        try:
            repo_version = migration.get_repo_version(repo_path)
            db_version = migration.get_db_version(self._engine, repo_path)

            if repo_version != db_version:
                msg = ('Database (%s) is not up to date (current=%s, '
                    'latest=%s); run `keystone-manage sync_database` or '
                    'override your migrate version manually (see docs)' %
                    (self.connection_str, db_version, repo_version))
                logging.warning(msg)
                raise Exception(msg)
        except versioning_exceptions.DatabaseNotControlledError:
            msg = ('Database (%s) is not version controlled; '
                'run `keystone-manage sync_database` or '
                'override your migrate version manually (see docs)' %
                (self.connection_str))
            logging.warning(msg)

    @staticmethod
    def _init_models(model_list):
        for model in model_list:
            model_class = getattr(models, model)
            top_models.set_value(model, model_class)

            if model_class.__api__ is not None:
                api_path = '.'.join([__package__, 'api', model_class.__api__])
                api_module = sys.modules.get(api_path)
                if api_module is None:
                    api_module = utils.import_module(api_path)
                top_api.set_value(model_class.__api__, api_module.get())

    def _init_tables(self, model_list):
        tables = []

        for model in model_list:
            model_class = getattr(models, model)
            tables.append(model_class.__table__)

        tables_to_create = []
        for table in reversed(models.Base.metadata.sorted_tables):
            if table in tables:
                tables_to_create.append(table)

        logger.debug('Creating tables: %s' % \
                ','.join([table.name for table in tables_to_create]))
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


def configure_backend(conf):
    global _DRIVER
    _DRIVER = Driver(conf)


def get_session():
    global _DRIVER
    return _DRIVER.get_session()


def unregister_models():
    global _DRIVER
    if _DRIVER:
        return _DRIVER.reset()
