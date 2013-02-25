# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

"""SQL backends for the various services."""
import functools

import sqlalchemy as sql
import sqlalchemy.engine.url
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.ext import declarative
import sqlalchemy.orm
import sqlalchemy.pool
from sqlalchemy import types as sql_types
from sqlalchemy.orm.attributes import InstrumentedAttribute

from keystone.common import logging
from keystone import config
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone import exception


CONF = config.CONF

# maintain a single engine reference for sqlite in-memory
GLOBAL_ENGINE = None


ModelBase = declarative.declarative_base()


# For exporting to other modules
Column = sql.Column
String = sql.String
ForeignKey = sql.ForeignKey
DateTime = sql.DateTime
IntegrityError = sql.exc.IntegrityError
NotFound = sql.orm.exc.NoResultFound
Boolean = sql.Boolean
Text = sql.Text
UniqueConstraint = sql.UniqueConstraint


def initialize_decorator(init):
    """Ensure that the length of string field do not exceed the limit.

    This decorator check the initialize arguments, to make sure the
    length of string field do not exceed the length limit, or raise a
    'StringLengthExceeded' exception.

    Use decorator instead of inheritance, because the metaclass will
    check the __tablename__, primary key columns, etc. at the class
    definition.

    """
    def initialize(self, *args, **kwargs):
        cls = type(self)
        for k, v in kwargs.items():
            if hasattr(cls, k):
                attr = getattr(cls, k)
                if isinstance(attr, InstrumentedAttribute):
                    column = attr.property.columns[0]
                    if isinstance(column.type, String):
                        if column.type.length and \
                                column.type.length < len(str(v)):
                            #if signing.token_format == 'PKI', the id will
                            #store it's public key which is very long.
                            if config.CONF.signing.token_format == 'PKI' and \
                                    self.__tablename__ == 'token' and \
                                    k == 'id':
                                continue

                            raise exception.StringLengthExceeded(
                                string=v, type=k, length=column.type.length)

        init(self, *args, **kwargs)
    return initialize

ModelBase.__init__ = initialize_decorator(ModelBase.__init__)


def set_global_engine(engine):
    global GLOBAL_ENGINE
    GLOBAL_ENGINE = engine


def get_global_engine():
    global GLOBAL_ENGINE
    return GLOBAL_ENGINE


# Special Fields
class JsonBlob(sql_types.TypeDecorator):

    impl = sql.Text

    def process_bind_param(self, value, dialect):
        return jsonutils.dumps(value)

    def process_result_value(self, value, dialect):
        return jsonutils.loads(value)


class DictBase(object):
    attributes = []

    @classmethod
    def from_dict(cls, d):
        new_d = d.copy()

        new_d['extra'] = dict((k, new_d.pop(k)) for k in d.iterkeys()
                              if k not in cls.attributes and k != 'extra')

        return cls(**new_d)

    def to_dict(self, include_extra_dict=False):
        """Returns the model's attributes as a dictionary.

        If include_extra_dict is True, 'extra' attributes are literally
        included in the resulting dictionary twice, for backwards-compatibility
        with a broken implementation.

        """
        d = self.extra.copy()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)

        if include_extra_dict:
            d['extra'] = self.extra.copy()

        return d

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __iter__(self):
        self._i = iter(sqlalchemy.orm.object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n

    def update(self, values):
        """Make the model object behave like a dict."""
        for k, v in values.iteritems():
            setattr(self, k, v)

    def iteritems(self):
        """Make the model object behave like a dict.

        Includes attributes from joins.

        """
        return dict([(k, getattr(self, k)) for k in self])
        #local = dict(self)
        #joined = dict([(k, v) for k, v in self.__dict__.iteritems()
        #               if not k[0] == '_'])
        #local.update(joined)
        #return local.iteritems()


class MySQLPingListener(object):

    """
    Ensures that MySQL connections checked out of the
    pool are alive.

    Borrowed from:
    http://groups.google.com/group/sqlalchemy/msg/a4ce563d802c929f

    Error codes caught:
    * 2006 MySQL server has gone away
    * 2013 Lost connection to MySQL server during query
    * 2014 Commands out of sync; you can't run this command now
    * 2045 Can't open shared memory; no answer from server (%lu)
    * 2055 Lost connection to MySQL server at '%s', system error: %d

    from http://dev.mysql.com/doc/refman/5.6/en/error-messages-client.html
    """

    def checkout(self, dbapi_con, con_record, con_proxy):
        try:
            dbapi_con.cursor().execute('select 1')
        except dbapi_con.OperationalError as e:
            if e.args[0] in (2006, 2013, 2014, 2045, 2055):
                logging.warn(_('Got mysql server has gone away: %s'), e)
                raise DisconnectionError("Database server went away")
            else:
                raise


# Backends
class Base(object):
    _engine = None
    _sessionmaker = None

    def get_session(self, autocommit=True, expire_on_commit=False):
        """Return a SQLAlchemy session."""
        self._engine = self._engine or self.get_engine()
        self._sessionmaker = self._sessionmaker or self.get_sessionmaker(
            self._engine)
        return self._sessionmaker()

    def get_engine(self, allow_global_engine=True):
        """Return a SQLAlchemy engine.

        If allow_global_engine is True and an in-memory sqlite connection
        string is provided by CONF, all backends will share a global sqlalchemy
        engine.

        """
        def new_engine():
            connection_dict = sql.engine.url.make_url(CONF.sql.connection)

            engine_config = {
                'convert_unicode': True,
                'echo': CONF.debug and CONF.verbose,
                'pool_recycle': CONF.sql.idle_timeout,
            }

            if 'sqlite' in connection_dict.drivername:
                engine_config['poolclass'] = sqlalchemy.pool.StaticPool
            elif 'mysql' in connection_dict.drivername:
                engine_config['listeners'] = [MySQLPingListener()]

            return sql.create_engine(CONF.sql.connection, **engine_config)

        engine = get_global_engine() or new_engine()

        # auto-build the db to support wsgi server w/ in-memory backend
        if allow_global_engine and CONF.sql.connection == 'sqlite://':
            ModelBase.metadata.create_all(bind=engine)
            set_global_engine(engine)

        return engine

    def get_sessionmaker(self, engine, autocommit=True,
                         expire_on_commit=False):
        """Return a SQLAlchemy sessionmaker using the given engine."""
        return sqlalchemy.orm.sessionmaker(
            bind=engine,
            autocommit=autocommit,
            expire_on_commit=expire_on_commit)


def handle_conflicts(type='object'):
    """Converts IntegrityError into HTTP 409 Conflict."""
    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except IntegrityError as e:
                raise exception.Conflict(type=type, details=str(e.orig))
        return wrapper
    return decorator
