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
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import joinedload, aliased, sessionmaker
from sqlalchemy.pool import StaticPool

from keystone.common import config
from keystone.backends.sqlalchemy import models
import keystone.utils as utils
import keystone.backends.api as top_api
import keystone.backends.models as top_models
_ENGINE = None
_MAKER = None
BASE = models.Base

MODEL_PREFIX = 'keystone.backends.sqlalchemy.models.'
API_PREFIX = 'keystone.backends.sqlalchemy.api.'


def configure_backend(options):
    """
    Establish the database, create an engine if needed, and
    register the models.

    :param options: Mapping of configuration options
    """
    global _ENGINE
    if not _ENGINE:
        debug = config.get_option(
            options, 'debug', type='bool', default=False)
        verbose = config.get_option(
            options, 'verbose', type='bool', default=False)
        timeout = config.get_option(
            options, 'sql_idle_timeout', type='int', default=3600)

        if options['sql_connection'] == "sqlite://":
            _ENGINE = create_engine(options['sql_connection'],
                                    connect_args={'check_same_thread': False},
                                    poolclass=StaticPool)
        else:
            _ENGINE = create_engine(options['sql_connection'],
                pool_recycle=timeout)

        logger = logging.getLogger('sqlalchemy.engine')
        if debug:
            logger.setLevel(logging.DEBUG)
        elif verbose:
            logger.setLevel(logging.INFO)

        register_models(options)


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _MAKER, _ENGINE
    if not _MAKER:
        assert _ENGINE
        _MAKER = sessionmaker(bind=_ENGINE,
                              autocommit=autocommit,
                              expire_on_commit=expire_on_commit)
    return _MAKER()


def register_models(options):
    """Register Models and create properties"""
    global _ENGINE
    assert _ENGINE
    # Need to decide.Not This is missing
    # and prevents foreign key reference checks.
    # _ENGINE.execute('pragma foreign_keys=on')
    supported_alchemy_models = ast.literal_eval(
                    options["backend_entities"])
    supported_alchemy_tables = []
    for supported_alchemy_model in supported_alchemy_models:
        model = utils.import_module(MODEL_PREFIX + supported_alchemy_model)
        supported_alchemy_tables.append(model.__table__)
        top_models.set_value(supported_alchemy_model, model)
        if model.__api__ is not None:
            model_api = utils.import_module(API_PREFIX + model.__api__)
            top_api.set_value(model.__api__, model_api.get())
    creation_tables = []
    for table in reversed(BASE.metadata.sorted_tables):
        if table in supported_alchemy_tables:
            creation_tables.append(table)
    BASE.metadata.create_all(_ENGINE, tables=creation_tables, checkfirst=True)


def unregister_models():
    """Unregister Models and reset _ENGINE,
    useful clearing out data before testing"""
    global _ENGINE
    if _ENGINE:
        BASE.metadata.drop_all(_ENGINE)
        _ENGINE = None
