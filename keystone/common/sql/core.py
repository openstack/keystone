# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""SQL backends for the various services."""


import json

import eventlet.db_pool
import sqlalchemy as sql
from sqlalchemy import types as sql_types
from sqlalchemy.ext import declarative
import sqlalchemy.orm
import sqlalchemy.pool
import sqlalchemy.engine.url

from keystone import config


CONF = config.CONF


ModelBase = declarative.declarative_base()


# For exporting to other modules
Column = sql.Column
String = sql.String
ForeignKey = sql.ForeignKey
DateTime = sql.DateTime


# Special Fields
class JsonBlob(sql_types.TypeDecorator):
    impl = sql.Text

    def process_bind_param(self, value, dialect):
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        return json.loads(value)


class DictBase(object):
    def to_dict(self):
        return dict(self.iteritems())

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


# Backends
class Base(object):
    _MAKER = None
    _ENGINE = None

    def get_session(self, autocommit=True, expire_on_commit=False):
        """Return a SQLAlchemy session."""
        if self._MAKER is None or self._ENGINE is None:
            self._ENGINE = self.get_engine()
            self._MAKER = self.get_maker(self._ENGINE,
                                         autocommit,
                                         expire_on_commit)

        session = self._MAKER()
        # TODO(termie): we may want to do something similar
        #session.query = nova.exception.wrap_db_error(session.query)
        #session.flush = nova.exception.wrap_db_error(session.flush)
        return session

    def get_engine(self):
        """Return a SQLAlchemy engine."""
        connection_dict = sqlalchemy.engine.url.make_url(CONF.sql.connection)

        engine_args = {'pool_recycle': CONF.sql.idle_timeout,
                       'echo': False,
                       'convert_unicode': True
                       }

        if 'sqlite' in connection_dict.drivername:
            engine_args['poolclass'] = sqlalchemy.pool.NullPool

        return sql.create_engine(CONF.sql.connection, **engine_args)

    def get_maker(self, engine, autocommit=True, expire_on_commit=False):
        """Return a SQLAlchemy sessionmaker using the given engine."""
        return sqlalchemy.orm.sessionmaker(bind=engine,
                                           autocommit=autocommit,
                                           expire_on_commit=expire_on_commit)
