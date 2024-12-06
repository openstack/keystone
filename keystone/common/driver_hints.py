# Copyright 2013 OpenStack Foundation
# Copyright 2013 IBM Corp.
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
import functools
import typing as ty

import keystone.conf
from keystone import exception
from keystone.i18n import _

CONF = keystone.conf.CONF


def truncated(f):
    """Ensure list truncation is detected in Driver list entity methods.

    This is designed to wrap Driver list_{entity} methods in order to
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
                _(
                    'Cannot truncate a driver call without hints list as '
                    'first parameter after self '
                )
            )

        if hints.limit is None or hints.filters:
            return f(self, hints, *args, **kwargs)

        # A limit is set, so ask for one more entry than we need
        list_limit = hints.limit['limit']
        hints.set_limit(list_limit + 1)
        ref_list = f(self, hints, *args, **kwargs)

        # If we got more than the original limit then trim back the list and
        # mark it truncated. In both cases, make sure we set the limit back
        # to its original value.
        if len(ref_list) > list_limit:
            hints.set_limit(list_limit, truncated=True)
            return ref_list[:list_limit]
        else:
            hints.set_limit(list_limit)
            return ref_list

    return wrapper


class Hints:
    """Encapsulate driver hints for listing entities.

    Hints are modifiers that affect the return of entities from a
    list_<entities> operation.  They are typically passed to a driver to give
    direction as to what filtering, pagination or list limiting actions are
    being requested.

    It is optional for a driver to action some or all of the list hints,
    but any filters that it does satisfy must be marked as such by calling
    removing the filter from the list.

    A Hint object contains filters, which is a list of dicts that can be
    accessed publicly. Also it contains a dict called limit, which will
    indicate the amount of data we want to limit our listing to.

    If the filter is discovered to never match, then `cannot_match` can be set
    to indicate that there will not be any matches and the backend work can be
    short-circuited.

    Each filter term consists of:

    * ``name``: the name of the attribute being matched
    * ``value``: the value against which it is being matched
    * ``comparator``: the operation, which can be one of ``equals``,
                      ``contains``, ``startswith`` or ``endswith``
    * ``case_sensitive``: whether any comparison should take account of
                          case

    """

    def __init__(self):
        self.limit: ty.Optional[dict[str, ty.Any]] = None
        self.marker: ty.Optional[str] = None
        self.filters = []
        self.cannot_match = False

    def add_filter(
        self,
        name,
        value,
        comparator: str = 'equals',
        case_sensitive: bool = False,
    ):
        """Add a filter to the filters list, which is publicly accessible."""
        self.filters.append(
            {
                'name': name,
                'value': value,
                'comparator': comparator,
                'case_sensitive': case_sensitive,
            }
        )

    def get_exact_filter_by_name(self, name):
        """Return a filter key and value if exact filter exists for name."""
        for entry in self.filters:
            if entry['name'] == name and entry['comparator'] == 'equals':
                return entry

    def set_limit(self, limit: int, truncated: bool = False):
        """Set a limit to indicate the list should be truncated."""
        self.limit = {'limit': limit, 'truncated': truncated}

    def get_limit_or_max(self) -> int:
        """Get page limit or max page size

        Return page limit (size) as requested by user (or API flow) or the
        maximum page size if not present. This method is invoked by the SQL
        drivers.

        :returns int: Page size
        """
        limit: ty.Optional[int] = (
            self.limit.get("limit") if self.limit else None
        )
        return int(limit) if limit else CONF.max_db_limit

    def get_limit_with_default(
        self, default_limit: ty.Optional[int] = None
    ) -> int:
        """Return page limit for the query.

        1. `limit` was set in the query parameters:
            `min(limit, MAX_LIMIT)`

        2. `limit` is not set and `default_limit` is set:
            `min(default_limit, MAX_LIMIT)`

        2. `limit` is null, `default_limit` is null, `CONF.list_limit` is set:
            `min(CONF.list_limit, MAX_LIMIT)`

        3. `limit` is null, `default_limit` is null, `CONF.list_limit` is null:
            `CONF.max_db_limit`

        """

        _user_limit: ty.Optional[int] = (
            self.limit.get("limit") if self.limit else None
        )
        _absolute_limit: int = CONF.max_db_limit
        # when default (as resource specific) is not set try to get the global
        # default
        _default_limit: ty.Optional[int] = default_limit or CONF.list_limit
        if _user_limit:
            return min(_user_limit, _absolute_limit)
        elif _default_limit:
            return min(_default_limit, _absolute_limit)
        else:
            return CONF.max_db_limit

    def set_marker(self, marker: str):
        """Set a marker pointing to the last entry of the page."""
        self.marker = marker
