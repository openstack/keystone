# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import calendar
import functools
import grp
import hashlib
import json
import os
import pwd

import passlib.hash

from keystone.common import config
from keystone.common import environment
from keystone import exception
from keystone.openstack.common import log as logging


CONF = config.CONF

LOG = logging.getLogger(__name__)


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file.

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


class SmarterEncoder(json.JSONEncoder):
    """Help for JSON encoding dict-like objects."""
    def default(self, obj):
        if not isinstance(obj, dict) and hasattr(obj, 'iteritems'):
            return dict(obj.iteritems())
        return super(SmarterEncoder, self).default(obj)


def trunc_password(password):
    """Truncate passwords to the max_length."""
    max_length = CONF.identity.max_password_length
    try:
        if len(password) > max_length:
            LOG.warning(
                _('Truncating user password to %s characters.'), max_length)
        return password[:max_length]
    except TypeError:
        raise exception.ValidationError(attribute='string', target='password')


def hash_access_key(access):
    hash_ = hashlib.sha256()
    hash_.update(access)
    return hash_.hexdigest()


def hash_user_password(user):
    """Hash a user dict's password without modifying the passed-in dict."""
    try:
        password = user['password']
    except KeyError:
        return user
    else:
        return dict(user, password=hash_password(password))


def hash_ldap_user_password(user):
    """Hash a user dict's password without modifying the passed-in dict."""
    try:
        password = user['password']
    except KeyError:
        return user
    else:
        return dict(user, password=ldap_hash_password(password))


def hash_password(password):
    """Hash a password. Hard."""
    password_utf8 = trunc_password(password).encode('utf-8')
    if passlib.hash.sha512_crypt.identify(password_utf8):
        return password_utf8
    h = passlib.hash.sha512_crypt.encrypt(password_utf8,
                                          rounds=CONF.crypt_strength)
    return h


def ldap_hash_password(password):
    """Hash a password. Hard."""
    password_utf8 = trunc_password(password).encode('utf-8')
    h = passlib.hash.ldap_salted_sha1.encrypt(password_utf8)
    return h


def ldap_check_password(password, hashed):
    if password is None:
        return False
    password_utf8 = trunc_password(password).encode('utf-8')
    return passlib.hash.ldap_salted_sha1.verify(password_utf8, hashed)


def check_password(password, hashed):
    """Check that a plaintext password matches hashed.

    hashpw returns the salt value concatenated with the actual hash value.
    It extracts the actual salt if this value is then passed as the salt.

    """
    if password is None or hashed is None:
        return False
    password_utf8 = trunc_password(password).encode('utf-8')
    return passlib.hash.sha512_crypt.verify(password_utf8, hashed)


# From python 2.7
def check_output(*popenargs, **kwargs):
    r"""Run command with arguments and return its output as a byte string.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> check_output(['ls', '-l', '/dev/null'])
    'crw-rw-rw- 1 root root 1, 3 Oct 18  2007 /dev/null\n'

    The stdout argument is not allowed as it is used internally.
    To capture standard error in the result, use stderr=STDOUT.

    >>> import sys
    >>> check_output(['/bin/sh', '-c',
    ...               'ls -l non_existent_file ; exit 0'],
    ...              stderr=sys.STDOUT)
    'ls: non_existent_file: No such file or directory\n'
    """
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    LOG.debug(' '.join(popenargs[0]))
    process = environment.subprocess.Popen(stdout=environment.subprocess.PIPE,
                                           *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = popenargs[0]
        raise environment.subprocess.CalledProcessError(retcode, cmd)
    return output


def get_blob_from_credential(credential):
    try:
        blob = json.loads(credential.blob)
    except (ValueError, TypeError):
        raise exception.ValidationError(
            message=_('Invalid blob in credential'))
    if not blob or not isinstance(blob, dict):
        raise exception.ValidationError(attribute='blob',
                                        target='credential')
    return blob


def convert_ec2_to_v3_credential(ec2credential):
    blob = {'access': ec2credential.access,
            'secret': ec2credential.secret}
    return {'id': hash_access_key(ec2credential.access),
            'user_id': ec2credential.user_id,
            'project_id': ec2credential.tenant_id,
            'blob': json.dumps(blob),
            'type': 'ec2',
            'extra': json.dumps({})}


def convert_v3_to_ec2_credential(credential):
    blob = get_blob_from_credential(credential)
    return {'access': blob.get('access'),
            'secret': blob.get('secret'),
            'user_id': credential.user_id,
            'tenant_id': credential.project_id,
            }


def git(*args):
    return check_output(['git'] + list(args))


def unixtime(dt_obj):
    """Format datetime object as unix timestamp

    :param dt_obj: datetime.datetime object
    :returns: float

    """
    return calendar.timegm(dt_obj.utctimetuple())


def auth_str_equal(provided, known):
    """Constant-time string comparison.

    :params provided: the first string
    :params known: the second string

    :return: True if the strings are equal.

    This function takes two strings and compares them.  It is intended to be
    used when doing a comparison for authentication purposes to help guard
    against timing attacks.  When using the function for this purpose, always
    provide the user-provided password as the first argument.  The time this
    function will take is always a factor of the length of this string.
    """
    result = 0
    p_len = len(provided)
    k_len = len(known)
    for i in xrange(p_len):
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
            LOG.exception(_(
                'Error setting up the debug environment. Verify that the '
                'option --debug-url has the format <host>:<port> and that a '
                'debugger processes is listening on that port.'))
            raise


class LimitingReader(object):
    """Reader to limit the size of an incoming request."""
    def __init__(self, data, limit):
        """Create an iterator on the underlying data.

        :param data: Underlying data object
        :param limit: maximum number of bytes the reader should allow
        """
        self.data = data
        self.limit = limit
        self.bytes_read = 0

    def __iter__(self):
        for chunk in self.data:
            self.bytes_read += len(chunk)
            if self.bytes_read > self.limit:
                raise exception.RequestTooLarge()
            else:
                yield chunk

    def read(self, i=None):
        # NOTE(jamielennox): We can't simply provide the default to the read()
        # call as the expected default differs between mod_wsgi and eventlet
        if i is None:
            result = self.data.read()
        else:
            result = self.data.read(i)
        self.bytes_read += len(result)
        if self.bytes_read > self.limit:
            raise exception.RequestTooLarge()
        return result


def get_unix_user(user=None):
    '''Get the uid and user name.

    This is a convenience utility which accepts a variety of input
    which might represent a unix user. If successful it returns the uid
    and name. Valid input is:

    string
        A string is first considered to be a user name and a lookup is
        attempted under that name. If no name is found then an attempt
        is made to convert the string to an integer and perform a
        lookup as a uid.

    int
        An integer is interpretted as a uid.

    None
        None is interpreted to mean use the current process's
        effective user.

    If the input is a valid type but no user is found a KeyError is
    raised. If the input is not a valid type a TypeError is raised.

    :param object user: string, int or None specifying the user to
                        lookup.

    :return: tuple of (uid, name)
    '''

    if isinstance(user, basestring):
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
        raise TypeError('user must be string, int or None; not %s (%r)' %
                        (user.__class__.__name__, user))

    return user_info.pw_uid, user_info.pw_name


def get_unix_group(group=None):
    '''Get the gid and group name.

    This is a convenience utility which accepts a variety of input
    which might represent a unix group. If successful it returns the gid
    and name. Valid input is:

    string
        A string is first considered to be a group name and a lookup is
        attempted under that name. If no name is found then an attempt
        is made to convert the string to an integer and perform a
        lookup as a gid.

    int
        An integer is interpretted as a gid.

    None
        None is interpreted to mean use the current process's
        effective group.

    If the input is a valid type but no group is found a KeyError is
    raised. If the input is not a valid type a TypeError is raised.


    :param object group: string, int or None specifying the group to
                         lookup.

    :return: tuple of (gid, name)
    '''

    if isinstance(group, basestring):
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
        raise TypeError('group must be string, int or None; not %s (%r)' %
                        (group.__class__.__name__, group))

    return group_info.gr_gid, group_info.gr_name


def set_permissions(path, mode=None, user=None, group=None, log=None):
    '''Set the ownership and permissions on the pathname.

    Each of the mode, user and group are optional, if None then
    that aspect is not modified.

    Owner and group may be specified either with a symbolic name
    or numeric id.

    :param string path: Pathname of directory whose existence is assured.
    :param object mode: ownership permissions flags (int) i.e. chmod,
                        if None do not set.
    :param object user: set user, name (string) or uid (integer),
                         if None do not set.
    :param object group: set group, name (string) or gid (integer)
                         if None do not set.
    :param logger log: logging.logger object, used to emit log messages,
                       if None no logging is performed.
    '''

    if user is None:
        user_uid, user_name = None, None
    else:
        user_uid, user_name = get_unix_user(user)

    if group is None:
        group_gid, group_name = None, None
    else:
        group_gid, group_name = get_unix_group(group)

    if log:
        if mode is None:
            mode_string = str(mode)
        else:
            mode_string = oct(mode)
        log.debug("set_permissions: "
                  "path='%s' mode=%s user=%s(%s) group=%s(%s)",
                  path, mode_string,
                  user_name, user_uid, group_name, group_gid)

    # Change user and group if specified
    if user_uid is not None or group_gid is not None:
        if user_uid is None:
            user_uid = -1
        if group_gid is None:
            group_gid = -1
        try:
            os.chown(path, user_uid, group_gid)
        except OSError as exc:
            raise EnvironmentError("chown('%s', %s, %s): %s" %
                                   (path,
                                    user_name, group_name,
                                    exc.strerror))

    # Change permission flags
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError as exc:
            raise EnvironmentError("chmod('%s', %#o): %s" %
                                   (path, mode, exc.strerror))


def make_dirs(path, mode=None, user=None, group=None, log=None):
    '''Assure directory exists, set ownership and permissions.

    Assure the directory exists and optionally set it's ownership
    and permissions.

    Each of the mode, user and group are optional, if None then
    that aspect is not modified.

    Owner and group may be specified either with a symbolic name
    or numeric id.

    :param string path: Pathname of directory whose existence is assured.
    :param object mode: ownership permissions flags (int) i.e. chmod,
                        if None do not set.
    :param object user: set user, name (string) or uid (integer),
                        if None do not set.
    :param object group: set group, name (string) or gid (integer)
                         if None do not set.
    :param logger log: logging.logger object, used to emit log messages,
                       if None no logging is performed.
    '''

    if log:
        if mode is None:
            mode_string = str(mode)
        else:
            mode_string = oct(mode)
        log.debug("make_dirs path='%s' mode=%s user=%s group=%s",
                  path, mode_string, user, group)

    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except OSError as exc:
            raise EnvironmentError("makedirs('%s'): %s" % (path, exc.strerror))

    set_permissions(path, mode, user, group, log)


class deprecated(object):
    """A decorator to mark callables as deprecated.

    deprecated logs a deprecation message when the callable it decorates
    is used. The message will include the release where the callable was
    deprecated, the release where is may be removed and possibly an
    optional replacement.

    Examples:

    1. Specifing the required deprecated release

    >>> @deprecated(as_of=deprecated.ICEHOUSE)
    ... def a(): pass

    2. Specifing a replacement:

    >>> @deprecated(as_of=deprecated.ICEHOUSE, in_favor_of='f()')
    ... def b(): pass

    3. Specifying the release where the functionality may be removed:

    >>> @deprecated(as_of=deprecated.ICEHOUSE, remove_in=+1)
    ... def c(): pass

    """

    FOLSOM = 'F'
    GRIZZLY = 'G'
    ICEHOUSE = 'I'

    _RELEASES = {
        'F': 'Folsom',
        'G': 'Grizzly',
        'H': 'Havana',
        'I': 'Icehouse',
    }

    _deprecated_msg_with_alternative = _(
        '%(what)s is deprecated as of %(as_of)s in favor of '
        '%(in_favor_of)s and may be removed in %(remove_in)s.')

    _deprecated_msg_no_alternative = _(
        '%(what)s is deprecated as of %(as_of)s and may be '
        'removed in %(remove_in)s. It will not be superseded.')

    def __init__(self, as_of, in_favor_of=None, remove_in=2, what=None):
        """Initialize decorator

        :param as_of: the release deprecating the callable. Constants
            are define in this class for convenience.
        :param in_favor_of: the replacement for the callable (optional)
        :param remove_in: an integer specifying how many releases to wait
            before removing (default: 2)
        :param what: name of the thing being deprecated (default: the
            callable's name)

        """
        self.as_of = as_of
        self.in_favor_of = in_favor_of
        self.remove_in = remove_in
        self.what = what

    def __call__(self, func):
        if not self.what:
            self.what = func.__name__ + '()'

        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            msg, details = self._build_message()
            LOG.deprecated(msg, details)
            return func(*args, **kwargs)
        return wrapped

    def _get_safe_to_remove_release(self, release):
        # TODO(dstanek): this method will have to be reimplemented once
        #    when we get to the X release because once we get to the Y
        #    release, what is Y+2?
        new_release = chr(ord(release) + self.remove_in)
        if new_release in self._RELEASES:
            return self._RELEASES[new_release]
        else:
            return new_release

    def _build_message(self):
        details = dict(what=self.what,
                       as_of=self._RELEASES[self.as_of],
                       remove_in=self._get_safe_to_remove_release(self.as_of))

        if self.in_favor_of:
            details['in_favor_of'] = self.in_favor_of
            msg = self._deprecated_msg_with_alternative
        else:
            msg = self._deprecated_msg_no_alternative
        return msg, details
