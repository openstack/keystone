# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
"""
Session Handling for SQLAlchemy backend
"""
import logging
import os

from sqlalchemy import create_engine
from sqlalchemy import pool
from sqlalchemy.orm import sessionmaker


_ENGINE = None
_MAKER = None


def get_connection_string():
    path = os.path.realpath(__file__)
    dbpath = os.path.normpath(os.path.join(path,
                                    os.pardir,   # sqlalchemy
                                    os.pardir,   # db
                                    os.pardir))  # keystone
    connection_string = "sqlite:///%s/keystone.db" % dbpath
    logging.debug('SQL ALchemy connection string: %s', connection_string)
    return connection_string


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _ENGINE
    global _MAKER
    if not _MAKER:
        if not _ENGINE:
            kwargs = {'pool_recycle': 30, 'echo': False}
            kwargs['poolclass'] = pool.NullPool  # for SQLite3
            _ENGINE = create_engine(get_connection_string(), **kwargs)
        _MAKER = (sessionmaker(bind=_ENGINE,
            autocommit=autocommit,
            expire_on_commit=expire_on_commit))
    session = _MAKER()
    return session


def get_engine():
    if not _ENGINE:
        raise
    return _ENGINE
