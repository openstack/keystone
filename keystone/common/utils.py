# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
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

import collections.abc
import contextlib
import grp
import hashlib
import itertools
import os
import pwd
import uuid

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import reflection
from oslo_utils import strutils
from oslo_utils import timeutils
import urllib


from keystone.common import password_hashing
import keystone.conf
from keystone import exception
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
WHITELISTED_PROPERTIES = [
    'tenant_id', 'project_id', 'user_id',
    'public_bind_host', 'admin_bind_host',
    'compute_host', 'admin_port', 'public_port',
    'public_endpoint', ]


# NOTE(stevermar): This UUID must stay the same, forever, across
# all of keystone to preserve its value as a URN namespace, which is
# used for ID transformation.
RESOURCE_ID_NAMESPACE = uuid.UUID('4332ecab-770b-4288-a680-b9aca3b1b153')

# Compatibilty for password hashing functions.
verify_length_and_trunc_password = password_hashing.verify_length_and_trunc_password  # noqa
hash_password = password_hashing.hash_password
hash_user_password = password_hashing.hash_user_password
check_password = password_hashing.check_password


def resource_uuid(value):
    """Convert input to valid UUID hex digits."""
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        if len(value) <= 64:
            return uuid.uuid5(RESOURCE_ID_NAMESPACE, value).hex
        raise ValueError(_('Length of transformable resource id > 64, '
                         'which is max allowed characters'))


def flatten_dict(d, parent_key=''):
    """Flatten a nested dictionary.

    Converts a dictionary with nested values to a single level flat
    dictionary, with dotted notation for each key.

    """
    items = []
    for k, v in d.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.abc.MutableMapping):
            items.extend(list(flatten_dict(v, new_key).items()))
        else:
            items.append((new_key, v))
    return dict(items)


class SmarterEncoder(jsonutils.json.JSONEncoder):
    """Help for JSON encoding dict-like objects."""

    def default(self, obj):
        if not isinstance(obj, dict) and hasattr(obj, 'items'):
            return dict(obj.items())
        return super(SmarterEncoder, self).default(obj)


def hash_access_key(access):
    hash_ = hashlib.sha256()
    if not isinstance(access, bytes):
        access = access.encode('utf-8')
    hash_.update(access)
    return hash_.hexdigest()


def attr_as_boolean(val_attr):
    """Return the boolean value, decoded from a string.

    We test explicitly for a value meaning False, which can be one of
    several formats as specified in oslo strutils.FALSE_STRINGS.
    All other string values (including an empty string) are treated as
    meaning True.

    """
    return strutils.bool_from_string(val_attr, default=True)


def auth_str_equal(provided, known):
    """Constant-time string comparison.

    :params provided: the first string
    :params known: the second string

    :returns: True if the strings are equal.

    This function takes two strings and compares them.  It is intended to be
    used when doing a comparison for authentication purposes to help guard
    against timing attacks.  When using the function for this purpose, always
    provide the user-provided password as the first argument.  The time this
    function will take is always a factor of the length of this string.
    """
    result = 0
    p_len = len(provided)
    k_len = len(known)
    for i in range(p_len):
        a = ord(provided[i]) if i < p_len else 0
        b = ord(known[i]) if i < k_len else 0
        result |= a ^ b
    return (p_len == k_len) & (result == 0)


def setup_remote_pydev_debug():
    if CONF.pydev_debug_host and CONF.pydev_debug_port:
        try:
            try:
                from pydev import pydevd
            except ImportError:
                import pydevd

            pydevd.settrace(CONF.pydev_debug_host,
                            port=CONF.pydev_debug_port,
                            stdoutToServer=True,
                            stderrToServer=True)
            return True
        except Exception:
            LOG.exception(
                'Error setting up the debug environment. Verify that the '
                'option --debug-url has the format <host>:<port> and that a '
                'debugger processes is listening on that port.')
            raise


def get_unix_user(user=None):
    """Get the uid and user name.

    This is a convenience utility which accepts a variety of input
    which might represent a unix user. If successful it returns the uid
    and name. Valid input is:

    string
        A string is first considered to be a user name and a lookup is
        attempted under that name. If no name is found then an attempt
        is made to convert the string to an integer and perform a
        lookup as a uid.

    int
        An integer is interpreted as a uid.

    None
        None is interpreted to mean use the current process's
        effective user.

    If the input is a valid type but no user is found a KeyError is
    raised. If the input is not a valid type a TypeError is raised.

    :param object user: string, int or None specifying the user to
                        lookup.

    :returns: tuple of (uid, name)

    """
    if isinstance(user, str):
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            try:
                i = int(user)
            except ValueError:
                raise KeyError("user name '%s' not found" % user)
            try:
                user_info = pwd.getpwuid(i)
            except KeyError:
                raise KeyError("user id %d not found" % i)
    elif isinstance(user, int):
        try:
            user_info = pwd.getpwuid(user)
        except KeyError:
            raise KeyError("user id %d not found" % user)
    elif user is None:
        user_info = pwd.getpwuid(os.geteuid())
    else:
        user_cls_name = reflection.get_class_name(user,
                                                  fully_qualified=False)
        raise TypeError('user must be string, int or None; not %s (%r)' %
                        (user_cls_name, user))

    return user_info.pw_uid, user_info.pw_name


def get_unix_group(group=None):
    """Get the gid and group name.

    This is a convenience utility which accepts a variety of input
    which might represent a unix group. If successful it returns the gid
    and name. Valid input is:

    string
        A string is first considered to be a group name and a lookup is
        attempted under that name. If no name is found then an attempt
        is made to convert the string to an integer and perform a
        lookup as a gid.

    int
        An integer is interpreted as a gid.

    None
        None is interpreted to mean use the current process's
        effective group.

    If the input is a valid type but no group is found a KeyError is
    raised. If the input is not a valid type a TypeError is raised.


    :param object group: string, int or None specifying the group to
                         lookup.

    :returns: tuple of (gid, name)

    """
    if isinstance(group, str):
        try:
            group_info = grp.getgrnam(group)
        except KeyError:
            # Was an int passed as a string?
            # Try converting to int and lookup by id instead.
            try:
                i = int(group)
            except ValueError:
                raise KeyError("group name '%s' not found" % group)
            try:
                group_info = grp.getgrgid(i)
            except KeyError:
                raise KeyError("group id %d not found" % i)
    elif isinstance(group, int):
        try:
            group_info = grp.getgrgid(group)
        except KeyError:
            raise KeyError("group id %d not found" % group)
    elif group is None:
        group_info = grp.getgrgid(os.getegid())
    else:
        group_cls_name = reflection.get_class_name(group,
                                                   fully_qualified=False)
        raise TypeError('group must be string, int or None; not %s (%r)' %
                        (group_cls_name, group))

    return group_info.gr_gid, group_info.gr_name


class WhiteListedItemFilter(object):

    def __init__(self, whitelist, data):
        self._whitelist = set(whitelist or [])
        self._data = data

    def __getitem__(self, name):
        """Evaluation on an item access."""
        if name not in self._whitelist:
            raise KeyError
        return self._data[name]


_ISO8601_TIME_FORMAT_SUBSECOND = '%Y-%m-%dT%H:%M:%S.%f'
_ISO8601_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


def isotime(at=None, subsecond=False):
    """Stringify time in ISO 8601 format.

    Python provides a similar instance method for datetime.datetime objects
    called `isoformat()`. The format of the strings generated by `isoformat()`
    has a couple of problems:

    1) The strings generated by `isotime()` are used in tokens and other public
    APIs that we can't change without a deprecation period. The strings
    generated by `isoformat()` are not the same format, so we can't just
    change to it.

    2) The strings generated by `isoformat()` do not include the microseconds
    if the value happens to be 0. This will likely show up as random
    failures as parsers may be written to always expect microseconds, and it
    will parse correctly most of the time.

    :param at: Optional datetime object to return at a string. If not provided,
               the time when the function was called will be used.
    :type at: datetime.datetime
    :param subsecond: If true, the returned string will represent microsecond
                      precision, but only precise to the second. For example, a
                      `datetime.datetime(2016, 9, 14, 14, 1, 13, 970223)` will
                      be returned as `2016-09-14T14:01:13.000000Z`.
    :type subsecond: bool
    :returns: A time string represented in ISO 8601 format.
    :rtype: str
    """
    if not at:
        at = timeutils.utcnow()
    # NOTE(lbragstad): Datetime objects are immutable, so reassign the date we
    # are working with to itself as we drop microsecond precision.
    at = at.replace(microsecond=0)
    st = at.strftime(_ISO8601_TIME_FORMAT
                     if not subsecond
                     else _ISO8601_TIME_FORMAT_SUBSECOND)
    tz = at.tzinfo.tzname(None) if at.tzinfo else 'UTC'
    # Need to handle either iso8601 or python UTC format
    st += ('Z' if tz in ['UTC', 'UTC+00:00'] else tz)
    return st


def parse_expiration_date(expiration_date):
    if not expiration_date.endswith('Z'):
        expiration_date += 'Z'
    try:
        expiration_time = timeutils.parse_isotime(expiration_date)
    except ValueError:
        raise exception.ValidationTimeStampError()
    if timeutils.is_older_than(expiration_time, 0):
        raise exception.ValidationExpirationError()
    return expiration_time


URL_RESERVED_CHARS = ":/?#[]@!$&'()*+,;="


def is_not_url_safe(name):
    """Check if a string contains any url reserved characters."""
    return len(list_url_unsafe_chars(name)) > 0


def list_url_unsafe_chars(name):
    """Return a list of the reserved characters."""
    reserved_chars = ''
    for i in name:
        if i in URL_RESERVED_CHARS:
            reserved_chars += i
    return reserved_chars


def lower_case_hostname(url):
    """Change the URL's hostname to lowercase."""
    # NOTE(gyee): according to
    # https://www.w3.org/TR/WD-html40-970708/htmlweb.html, the netloc portion
    # of the URL is case-insensitive
    parsed = urllib.parse.urlparse(url)
    # Note: _replace method for named tuples is public and defined in docs
    replaced = parsed._replace(netloc=parsed.netloc.lower())
    return urllib.parse.urlunparse(replaced)


def remove_standard_port(url):
    # remove the default ports specified in RFC2616 and 2818
    o = urllib.parse.urlparse(url)
    separator = ':'
    (host, separator, port) = o.netloc.partition(separator)
    if o.scheme.lower() == 'http' and port == '80':
        # NOTE(gyee): _replace() is not a private method. It has
        # an underscore prefix to prevent conflict with field names.
        # See https://docs.python.org/2/library/collections.html#
        # collections.namedtuple
        o = o._replace(netloc=host)
    if o.scheme.lower() == 'https' and port == '443':
        o = o._replace(netloc=host)

    return urllib.parse.urlunparse(o)


def format_url(url, substitutions, silent_keyerror_failures=None):
    """Format a user-defined URL with the given substitutions.

    :param string url: the URL to be formatted
    :param dict substitutions: the dictionary used for substitution
    :param list silent_keyerror_failures: keys for which we should be silent
        if there is a KeyError exception on substitution attempt
    :returns: a formatted URL

    """
    substitutions = WhiteListedItemFilter(
        WHITELISTED_PROPERTIES,
        substitutions)
    allow_keyerror = silent_keyerror_failures or []
    try:
        result = url.replace('$(', '%(') % substitutions
    except AttributeError:
        msg = "Malformed endpoint - %(url)r is not a string"
        LOG.error(msg, {"url": url})
        raise exception.MalformedEndpoint(endpoint=url)
    except KeyError as e:
        if not e.args or e.args[0] not in allow_keyerror:
            msg = "Malformed endpoint %(url)s - unknown key %(keyerror)s"
            LOG.error(msg, {"url": url, "keyerror": e})
            raise exception.MalformedEndpoint(endpoint=url)
        else:
            result = None
    except TypeError as e:
        msg = ("Malformed endpoint '%(url)s'. The following type error "
               "occurred during string substitution: %(typeerror)s")
        LOG.error(msg, {"url": url, "typeerror": e})
        raise exception.MalformedEndpoint(endpoint=url)
    except ValueError:
        msg = ("Malformed endpoint %s - incomplete format "
               "(are you missing a type notifier ?)")
        LOG.error(msg, url)
        raise exception.MalformedEndpoint(endpoint=url)
    return result


def check_endpoint_url(url):
    """Check substitution of url.

    The invalid urls are as follows:
    urls with substitutions that is not in the whitelist

    Check the substitutions in the URL to make sure they are valid
    and on the whitelist.

    :param str url: the URL to validate
    :rtype: None
    :raises keystone.exception.URLValidationError: if the URL is invalid
    """
    # check whether the property in the path is exactly the same
    # with that in the whitelist below
    substitutions = dict(zip(WHITELISTED_PROPERTIES, itertools.repeat('')))
    try:
        url.replace('$(', '%(') % substitutions
    except (KeyError, TypeError, ValueError):
        raise exception.URLValidationError(url=url)


def create_directory(directory, keystone_user_id=None, keystone_group_id=None):
    """Attempt to create a directory if it doesn't exist.

    :param directory: string containing the path of the directory to create.
    :param keystone_user_id: the system ID of the process running keystone.
    :param keystone_group_id: the system ID of the group running keystone.

    """
    if not os.access(directory, os.F_OK):
        LOG.info(
            '%s does not appear to exist; attempting to create it', directory
        )

        try:
            os.makedirs(directory, 0o700)
        except OSError:
            LOG.error(
                'Failed to create %s: either it already '
                'exists or you don\'t have sufficient permissions to '
                'create it', directory
            )

        if keystone_user_id and keystone_group_id:
            os.chown(
                directory,
                keystone_user_id,
                keystone_group_id)
        elif keystone_user_id or keystone_group_id:
            LOG.warning(
                'Unable to change the ownership of key repository without '
                'a keystone user ID and keystone group ID both being '
                'provided: %s', directory)


@contextlib.contextmanager
def nested_contexts(*contexts):
    with contextlib.ExitStack() as stack:
        yield [stack.enter_context(c) for c in contexts]
