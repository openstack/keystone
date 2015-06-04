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
import contextlib
import functools

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import models
from oslo_db.sqlalchemy import session as db_session
from oslo_log import log
from oslo_serialization import jsonutils
import six
import sqlalchemy as sql
from sqlalchemy.ext import declarative
from sqlalchemy.orm.attributes import flag_modified, InstrumentedAttribute
from sqlalchemy import types as sql_types

from keystone.common import utils
from keystone import exception
from keystone.i18n import _


CONF = cfg.CONF
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


def initialize():
    """Initialize the module."""

    db_options.set_defaults(
        CONF,
        connection="sqlite:///keystone.db")


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
                        if not isinstance(v, six.text_type):
                            v = six.text_type(v)
                        if column.type.length and column.type.length < len(v):
                            raise exception.StringLengthExceeded(
                                string=v, type=k, length=column.type.length)

        init(self, *args, **kwargs)
    return initialize

ModelBase.__init__ = initialize_decorator(ModelBase.__init__)


# Special Fields
class JsonBlob(sql_types.TypeDecorator):

    impl = sql.Text

    def process_bind_param(self, value, dialect):
        return jsonutils.dumps(value)

    def process_result_value(self, value, dialect):
        return jsonutils.loads(value)


class DictBase(models.ModelBase):
    attributes = []

    @classmethod
    def from_dict(cls, d):
        new_d = d.copy()

        new_d['extra'] = {k: new_d.pop(k) for k in six.iterkeys(d)
                          if k not in cls.attributes and k != 'extra'}

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

    def __getitem__(self, key):
        if key in self.extra:
            return self.extra[key]
        return getattr(self, key)


class ModelDictMixin(object):

    @classmethod
    def from_dict(cls, d):
        """Returns a model instance from a dictionary."""
        return cls(**d)

    def to_dict(self):
        """Returns the model's attributes as a dictionary."""
        names = (column.name for column in self.__table__.columns)
        return {name: getattr(self, name) for name in names}


_engine_facade = None


def _get_engine_facade():
    global _engine_facade

    if not _engine_facade:
        _engine_facade = db_session.EngineFacade.from_config(CONF)

    return _engine_facade


def cleanup():
    global _engine_facade

    _engine_facade = None


def get_engine():
    return _get_engine_facade().get_engine()


def get_session(expire_on_commit=False):
    return _get_engine_facade().get_session(expire_on_commit=expire_on_commit)


@contextlib.contextmanager
def transaction(expire_on_commit=False):
    """Return a SQLAlchemy session in a scoped transaction."""
    session = get_session(expire_on_commit=expire_on_commit)
    with session.begin():
        yield session


def truncated(f):
    """Ensure list truncation is detected in Driver list entity methods.

    This is designed to wrap and sql Driver list_{entity} methods in order to
    calculate if the resultant list has been truncated. Provided a limit dict
    is found in the hints list, we increment the limit by one so as to ask the
    wrapped function for one more entity than the limit, and then once the list
    has been generated, we check to see if the original limit has been
    exceeded, in which case we truncate back to that limit and set the
    'truncated' boolean to 'true' in the hints limit dict.

    """
    @functools.wraps(f)
    def wrapper(self, hints, *args, **kwargs):
        if not hasattr(hints, 'limit'):
            raise exception.UnexpectedError(
                _('Cannot truncate a driver call without hints list as '
                  'first parameter after self '))

        if hints.limit is None:
            return f(self, hints, *args, **kwargs)

        # A limit is set, so ask for one more entry than we need
        list_limit = hints.limit['limit']
        hints.set_limit(list_limit + 1)
        ref_list = f(self, hints, *args, **kwargs)

        # If we got more than the original limit then trim back the list and
        # mark it truncated.  In both cases, make sure we set the limit back
        # to its original value.
        if len(ref_list) > list_limit:
            hints.set_limit(list_limit, truncated=True)
            return ref_list[:list_limit]
        else:
            hints.set_limit(list_limit)
            return ref_list
    return wrapper


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
    """Applies filtering to a query.

    :param model: the table model in question
    :param query: query to apply filters to
    :param hints: contains the list of filters yet to be satisfied.
                  Any filters satisfied here will be removed so that
                  the caller will know if any filters remain.

    :returns query: query, updated with any filters satisfied

    """
    def inexact_filter(model, query, filter_, satisfied_filters):
        """Applies an inexact filter to a query.

        :param model: the table model in question
        :param query: query to apply filters to
        :param dict filter_: describes this filter
        :param list satisfied_filters: filter_ will be added if it is
                                       satisfied.

        :returns query: query updated to add any inexact filters we could
                        satisfy

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

    def exact_filter(model, filter_, cumulative_filter_dict):
        """Applies an exact filter to a query.

        :param model: the table model in question
        :param dict filter_: describes this filter
        :param dict cumulative_filter_dict: describes the set of exact filters
                                            built up so far

        """
        key = filter_['name']

        col = getattr(model, key)
        if isinstance(col.property.columns[0].type, sql.types.Boolean):
            cumulative_filter_dict[key] = (
                utils.attr_as_boolean(filter_['value']))
        else:
            _WontMatch.check(filter_['value'], col)
            cumulative_filter_dict[key] = filter_['value']

    try:
        filter_dict = {}
        satisfied_filters = []
        for filter_ in hints.filters:
            if filter_['name'] not in model.attributes:
                continue
            if filter_['comparator'] == 'equals':
                exact_filter(model, filter_, filter_dict)
                satisfied_filters.append(filter_)
            else:
                query = inexact_filter(model, query, filter_,
                                       satisfied_filters)

        # Apply any exact filters we built up
        if filter_dict:
            query = query.filter_by(**filter_dict)

        # Remove satisfied filters, then the caller will know remaining filters
        for filter_ in satisfied_filters:
            hints.filters.remove(filter_)

        return query
    except _WontMatch:
        hints.cannot_match = True
        return


def _limit(query, hints):
    """Applies a limit to a query.

    :param query: query to apply filters to
    :param hints: contains the list of filters and limit details.

    :returns updated query

    """
    # NOTE(henry-nash): If we were to implement pagination, then we
    # we would expand this method to support pagination and limiting.

    # If we satisfied all the filters, set an upper limit if supplied
    if hints.limit:
        query = query.limit(hints.limit['limit'])
    return query


def filter_limit_query(model, query, hints):
    """Applies filtering and limit to a query.

    :param model: table model
    :param query: query to apply filters to
    :param hints: contains the list of filters and limit details.  This may
                  be None, indicating that there are no filters or limits
                  to be applied. If it's not None, then any filters
                  satisfied here will be removed so that the caller will
                  know if any filters remain.

    :returns: updated query

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
    """Converts select sqlalchemy exceptions into HTTP 409 Conflict."""
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
                                          'details': six.text_type(e)})
                raise exception.Conflict(type=conflict_type,
                                         details=_('Duplicate Entry'))
            except db_exception.DBError as e:
                # TODO(blk-u): inspecting inner_exception breaks encapsulation;
                # oslo_db should provide exception we need.
                if isinstance(e.inner_exception, IntegrityError):
                    # LOG the exception for debug purposes, do not send the
                    # exception details out with the raised Conflict exception
                    # as it can contain raw SQL.
                    LOG.debug(_conflict_msg, {'conflict_type': conflict_type,
                                              'details': six.text_type(e)})
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
