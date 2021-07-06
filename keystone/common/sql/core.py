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

"""SQL backends for the various services.

Before using this module, call initialize(). This has to be done before
CONF() because it sets up configuration options.

"""
import datetime
import functools
import pytz

from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import models
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from osprofiler import opts as profiler
import osprofiler.sqlalchemy
import sqlalchemy as sql
from sqlalchemy.ext import declarative
from sqlalchemy.orm.attributes import flag_modified, InstrumentedAttribute
from sqlalchemy import types as sql_types

from keystone.common import driver_hints
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

ModelBase = declarative.declarative_base()


# For exporting to other modules
Column = sql.Column
Index = sql.Index
String = sql.String
Integer = sql.Integer
Enum = sql.Enum
ForeignKey = sql.ForeignKey
DateTime = sql.DateTime
Date = sql.Date
TIMESTAMP = sql.TIMESTAMP
IntegrityError = sql.exc.IntegrityError
DBDuplicateEntry = db_exception.DBDuplicateEntry
OperationalError = sql.exc.OperationalError
NotFound = sql.orm.exc.NoResultFound
Boolean = sql.Boolean
Text = sql.Text
UniqueConstraint = sql.UniqueConstraint
PrimaryKeyConstraint = sql.PrimaryKeyConstraint
joinedload = sql.orm.joinedload
# Suppress flake8's unused import warning for flag_modified:
flag_modified = flag_modified
Unicode = sql.Unicode


def initialize():
    """Initialize the module."""
    db_options.set_defaults(
        CONF,
        connection="sqlite:///keystone.db")
    # Configure OSprofiler options
    profiler.set_defaults(CONF, enabled=False, trace_sqlalchemy=False)


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
                        if not isinstance(v, str):
                            v = str(v)
                        if column.type.length and column.type.length < len(v):
                            raise exception.StringLengthExceeded(
                                string=v, type=k, length=column.type.length)

        init(self, *args, **kwargs)
    return initialize


ModelBase.__init__ = initialize_decorator(ModelBase.__init__)


# Special Fields
class JsonBlob(sql_types.TypeDecorator):

    impl = sql.Text
    # NOTE(ralonsoh): set to True as any other TypeDecorator in SQLAlchemy
    # https://docs.sqlalchemy.org/en/14/core/custom_types.html# \
    #   sqlalchemy.types.TypeDecorator.cache_ok
    cache_ok = True
    """This type is safe to cache."""

    def process_bind_param(self, value, dialect):
        return jsonutils.dumps(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            value = jsonutils.loads(value)
        return value


class DateTimeInt(sql_types.TypeDecorator):
    """A column that automatically converts a datetime object to an Int.

    Keystone relies on accurate (sub-second) datetime objects. In some cases
    the RDBMS drop sub-second accuracy (some versions of MySQL). This field
    automatically converts the value to an INT when storing the data and
    back to a datetime object when it is loaded from the database.

    NOTE: Any datetime object that has timezone data will be converted to UTC.
          Any datetime object that has no timezone data will be assumed to be
          UTC and loaded from the DB as such.
    """

    impl = sql.BigInteger
    epoch = datetime.datetime.fromtimestamp(0, tz=pytz.UTC)
    # NOTE(ralonsoh): set to True as any other TypeDecorator in SQLAlchemy
    # https://docs.sqlalchemy.org/en/14/core/custom_types.html# \
    #   sqlalchemy.types.TypeDecorator.cache_ok
    cache_ok = True
    """This type is safe to cache."""

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, datetime.datetime):
                raise ValueError(_('Programming Error: value to be stored '
                                   'must be a datetime object.'))
            value = timeutils.normalize_time(value)
            value = value.replace(tzinfo=pytz.UTC)
            # NOTE(morgan): We are casting this to an int, and ensuring we
            # preserve microsecond data by moving the decimal. This is easier
            # than being concerned with the differences in Numeric types in
            # different SQL backends.
            return int((value - self.epoch).total_seconds() * 1000000)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        else:
            # Convert from INT to appropriate micro-second float (microseconds
            # after the decimal) from what was stored to the DB
            value = float(value) / 1000000
            # NOTE(morgan): Explictly use timezone "pytz.UTC" to ensure we are
            # not adjusting the actual datetime object from what we stored.
            dt_obj = datetime.datetime.fromtimestamp(value, tz=pytz.UTC)
            # Return non-tz aware datetime object (as keystone expects)
            return timeutils.normalize_time(dt_obj)


class ModelDictMixinWithExtras(models.ModelBase):
    """Mixin making model behave with dict-like interfaces includes extras.

    NOTE: DO NOT USE THIS FOR FUTURE SQL MODELS. "Extra" column is a legacy
          concept that should not be carried forward with new SQL models
          as the concept of "arbitrary" properties is not in line with
          the design philosophy of Keystone.
    """

    attributes = []
    _msg = ('Programming Error: Model does not have an "extra" column. '
            'Unless the model already has an "extra" column and has '
            'existed in a previous released version of keystone with '
            'the extra column included, the model should use '
            '"ModelDictMixin" instead.')

    @classmethod
    def from_dict(cls, d):
        new_d = d.copy()

        if not hasattr(cls, 'extra'):
            # NOTE(notmorgan): No translation here, This is an error for
            # programmers NOT end users.
            raise AttributeError(cls._msg)  # no qa

        new_d['extra'] = {k: new_d.pop(k) for k in d.keys()
                          if k not in cls.attributes and k != 'extra'}

        return cls(**new_d)

    def to_dict(self, include_extra_dict=False):
        """Return the model's attributes as a dictionary.

        If include_extra_dict is True, 'extra' attributes are literally
        included in the resulting dictionary twice, for backwards-compatibility
        with a broken implementation.

        """
        if not hasattr(self, 'extra'):
            # NOTE(notmorgan): No translation here, This is an error for
            # programmers NOT end users.
            raise AttributeError(self._msg)  # no qa

        d = self.extra.copy()
        for attr in self.__class__.attributes:
            d[attr] = getattr(self, attr)

        if include_extra_dict:
            d['extra'] = self.extra.copy()

        return d

    def __getitem__(self, key):
        """Evaluate if key is in extra or not, to return correct item."""
        if key in self.extra:
            return self.extra[key]
        return getattr(self, key)


class ModelDictMixin(models.ModelBase):

    @classmethod
    def from_dict(cls, d):
        """Return a model instance from a dictionary."""
        return cls(**d)

    def to_dict(self):
        """Return the model's attributes as a dictionary."""
        names = (column.name for column in self.__table__.columns)
        return {name: getattr(self, name) for name in names}


_main_context_manager = None


def _get_main_context_manager():
    global _main_context_manager

    if not _main_context_manager:
        _main_context_manager = enginefacade.transaction_context()

    return _main_context_manager


# Now this function is only used for testing FK with sqlite.
def enable_sqlite_foreign_key():
    global _main_context_manager
    if not _main_context_manager:
        _main_context_manager = enginefacade.transaction_context()
        _main_context_manager.configure(sqlite_fk=True)


def cleanup():
    global _main_context_manager

    _main_context_manager = None


_CONTEXT = None


def _get_context():
    global _CONTEXT
    if _CONTEXT is None:
        # NOTE(dims): Delay the `threading.local` import to allow for
        # eventlet/gevent monkeypatching to happen
        import threading
        _CONTEXT = threading.local()
    return _CONTEXT


# Unit tests set this to True so that oslo.db's global engine is used.
# This allows oslo_db.test_base.DbTestCase to override the transaction manager
# with its test transaction manager.
_TESTING_USE_GLOBAL_CONTEXT_MANAGER = False


def session_for_read():
    if _TESTING_USE_GLOBAL_CONTEXT_MANAGER:
        reader = enginefacade.reader
    else:
        reader = _get_main_context_manager().reader
    return _wrap_session(reader.using(_get_context()))


def session_for_write():
    if _TESTING_USE_GLOBAL_CONTEXT_MANAGER:
        writer = enginefacade.writer
    else:
        writer = _get_main_context_manager().writer
    return _wrap_session(writer.using(_get_context()))


def _wrap_session(sess):
    if CONF.profiler.enabled and CONF.profiler.trace_sqlalchemy:
        sess = osprofiler.sqlalchemy.wrap_session(sql, sess)
    return sess


def truncated(f):
    return driver_hints.truncated(f)


class _WontMatch(Exception):
    """Raised to indicate that the filter won't match.

    This is raised to short-circuit the computation of the filter as soon as
    it's discovered that the filter requested isn't going to match anything.

    A filter isn't going to match anything if the value is too long for the
    field, for example.

    """

    @classmethod
    def check(cls, value, col_attr):
        """Check if the value can match given the column attributes.

        Raises this class if the value provided can't match any value in the
        column in the table given the column's attributes. For example, if the
        column is a string and the value is longer than the column then it
        won't match any value in the column in the table.

        """
        if value is None:
            return
        col = col_attr.property.columns[0]
        if isinstance(col.type, sql.types.Boolean):
            # The column is a Boolean, we should have already validated input.
            return
        if not col.type.length:
            # The column doesn't have a length so can't validate anymore.
            return
        if len(value) > col.type.length:
            raise cls()
        # Otherwise the value could match a value in the column.


def _filter(model, query, hints):
    """Apply filtering to a query.

    :param model: the table model in question
    :param query: query to apply filters to
    :param hints: contains the list of filters yet to be satisfied.
                  Any filters satisfied here will be removed so that
                  the caller will know if any filters remain.

    :returns: query updated with any filters satisfied

    """
    def inexact_filter(model, query, filter_, satisfied_filters):
        """Apply an inexact filter to a query.

        :param model: the table model in question
        :param query: query to apply filters to
        :param dict filter_: describes this filter
        :param list satisfied_filters: filter_ will be added if it is
                                       satisfied.

        :returns: query updated to add any inexact filters satisfied

        """
        column_attr = getattr(model, filter_['name'])

        # TODO(henry-nash): Sqlalchemy 0.7 defaults to case insensitivity
        # so once we find a way of changing that (maybe on a call-by-call
        # basis), we can add support for the case sensitive versions of
        # the filters below.  For now, these case sensitive versions will
        # be handled at the controller level.

        if filter_['case_sensitive']:
            return query

        if filter_['comparator'] == 'contains':
            _WontMatch.check(filter_['value'], column_attr)
            query_term = column_attr.ilike('%%%s%%' % filter_['value'])
        elif filter_['comparator'] == 'startswith':
            _WontMatch.check(filter_['value'], column_attr)
            query_term = column_attr.ilike('%s%%' % filter_['value'])
        elif filter_['comparator'] == 'endswith':
            _WontMatch.check(filter_['value'], column_attr)
            query_term = column_attr.ilike('%%%s' % filter_['value'])
        else:
            # It's a filter we don't understand, so let the caller
            # work out if they need to do something with it.
            return query

        satisfied_filters.append(filter_)
        return query.filter(query_term)

    def exact_filter(model, query, filter_, satisfied_filters):
        """Apply an exact filter to a query.

        :param model: the table model in question
        :param query: query to apply filters to
        :param dict filter_: describes this filter
        :param list satisfied_filters: filter_ will be added if it is
                                       satisfied.
        :returns: query updated to add any exact filters satisfied
        """
        key = filter_['name']

        col = getattr(model, key)
        if isinstance(col.property.columns[0].type, sql.types.Boolean):
            filter_val = utils.attr_as_boolean(filter_['value'])
        else:
            _WontMatch.check(filter_['value'], col)
            filter_val = filter_['value']

        satisfied_filters.append(filter_)
        return query.filter(col == filter_val)

    try:
        satisfied_filters = []
        for filter_ in hints.filters:
            if filter_['name'] not in model.attributes:
                continue
            if filter_['comparator'] == 'equals':
                query = exact_filter(model, query, filter_,
                                     satisfied_filters)
            else:
                query = inexact_filter(model, query, filter_,
                                       satisfied_filters)

        # Remove satisfied filters, then the caller will know remaining filters
        for filter_ in satisfied_filters:
            hints.filters.remove(filter_)

        return query
    except _WontMatch:
        hints.cannot_match = True
        return


def _limit(query, hints):
    """Apply a limit to a query.

    :param query: query to apply filters to
    :param hints: contains the list of filters and limit details.

    :returns: query updated with any limits satisfied

    """
    # NOTE(henry-nash): If we were to implement pagination, then we
    # we would expand this method to support pagination and limiting.

    # If we satisfied all the filters, set an upper limit if supplied
    if hints.limit:
        original_len = query.count()
        limit_query = query.limit(hints.limit['limit'])
        if limit_query.count() < original_len:
            hints.limit['truncated'] = True
            query = limit_query
    return query


def filter_limit_query(model, query, hints):
    """Apply filtering and limit to a query.

    :param model: table model
    :param query: query to apply filters to
    :param hints: contains the list of filters and limit details.  This may
                  be None, indicating that there are no filters or limits
                  to be applied. If it's not None, then any filters
                  satisfied here will be removed so that the caller will
                  know if any filters remain.

    :returns: query updated with any filters and limits satisfied

    """
    if hints is None:
        return query

    # First try and satisfy any filters
    query = _filter(model, query, hints)

    if hints.cannot_match:
        # Nothing's going to match, so don't bother with the query.
        return []

    # NOTE(henry-nash): Any unsatisfied filters will have been left in
    # the hints list for the controller to handle. We can only try and
    # limit here if all the filters are already satisfied since, if not,
    # doing so might mess up the final results. If there are still
    # unsatisfied filters, we have to leave any limiting to the controller
    # as well.

    if not hints.filters:
        return _limit(query, hints)
    else:
        return query


def handle_conflicts(conflict_type='object'):
    """Convert select sqlalchemy exceptions into HTTP 409 Conflict."""
    _conflict_msg = 'Conflict %(conflict_type)s: %(details)s'

    def decorator(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except db_exception.DBDuplicateEntry as e:
                # LOG the exception for debug purposes, do not send the
                # exception details out with the raised Conflict exception
                # as it can contain raw SQL.
                LOG.debug(_conflict_msg, {'conflict_type': conflict_type,
                                          'details': e})
                name = None
                field = None
                domain_id = None
                # First element is unnecessary for extracting name and causes
                # object not iterable error. Remove it.
                params = args[1:]
                # We want to store the duplicate objects name in the error
                # message for the user. If name is not available we use the id.
                for arg in params:
                    if isinstance(arg, dict):
                        if 'name' in arg:
                            field = 'name'
                            name = arg['name']
                        elif 'id' in arg:
                            field = 'ID'
                            name = arg['id']
                        if 'domain_id' in arg:
                            domain_id = arg['domain_id']
                msg = _('Duplicate entry')
                if name and domain_id:
                    msg = _('Duplicate entry found with %(field)s %(name)s '
                            'at domain ID %(domain_id)s') % {
                        'field': field, 'name': name, 'domain_id': domain_id}
                elif name:
                    msg = _('Duplicate entry found with %(field)s '
                            '%(name)s') % {'field': field, 'name': name}
                elif domain_id:
                    msg = (_('Duplicate entry at domain ID %s') % domain_id)
                raise exception.Conflict(type=conflict_type,
                                         details=msg)
            except db_exception.DBError as e:
                # TODO(blk-u): inspecting inner_exception breaks encapsulation;
                # oslo_db should provide exception we need.
                if isinstance(e.inner_exception, IntegrityError):
                    # LOG the exception for debug purposes, do not send the
                    # exception details out with the raised Conflict exception
                    # as it can contain raw SQL.
                    LOG.debug(_conflict_msg, {'conflict_type': conflict_type,
                                              'details': e})
                    # NOTE(morganfainberg): This is really a case where the SQL
                    # failed to store the data. This is not something that the
                    # user has done wrong. Example would be a ForeignKey is
                    # missing; the code that is executed before reaching the
                    # SQL writing to the DB should catch the issue.
                    raise exception.UnexpectedError(
                        _('An unexpected error occurred when trying to '
                          'store %s') % conflict_type)
                raise

        return wrapper
    return decorator
