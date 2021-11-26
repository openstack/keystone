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

import abc
import codecs
import os.path
import re
import sys
import uuid
import weakref

import ldap.controls
import ldap.filter
import ldappool
from oslo_log import log
from oslo_utils import reflection

from keystone.common import driver_hints
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)

LDAP_VALUES = {'TRUE': True, 'FALSE': False}
LDAP_SCOPES = {'one': ldap.SCOPE_ONELEVEL,
               'sub': ldap.SCOPE_SUBTREE}
LDAP_DEREF = {'always': ldap.DEREF_ALWAYS,
              'default': None,
              'finding': ldap.DEREF_FINDING,
              'never': ldap.DEREF_NEVER,
              'searching': ldap.DEREF_SEARCHING}
LDAP_TLS_CERTS = {'never': ldap.OPT_X_TLS_NEVER,
                  'demand': ldap.OPT_X_TLS_DEMAND,
                  'allow': ldap.OPT_X_TLS_ALLOW}


# RFC 4511 (The LDAP Protocol) defines a list containing only the OID '1.1' to
# indicate that no attributes should be returned besides the DN.
DN_ONLY = ['1.1']

_utf8_encoder = codecs.getencoder('utf-8')

# FIXME(knikolla): This enables writing to the LDAP backend
# Only enabled during tests and unsupported
WRITABLE = False


def utf8_encode(value):
    """Encode a basestring to UTF-8.

    If the string is unicode encode it to UTF-8, if the string is
    str then assume it's already encoded. Otherwise raise a TypeError.

    :param value: A basestring
    :returns: UTF-8 encoded version of value
    :raises TypeError: If value is not basestring
    """
    if isinstance(value, str):
        return _utf8_encoder(value)[0]
    elif isinstance(value, bytes):
        return value
    else:
        value_cls_name = reflection.get_class_name(
            value, fully_qualified=False)
        raise TypeError("value must be basestring, "
                        "not %s" % value_cls_name)


_utf8_decoder = codecs.getdecoder('utf-8')


def utf8_decode(value):
    """Decode a from UTF-8 into unicode.

    If the value is a binary string assume it's UTF-8 encoded and decode
    it into a unicode string. Otherwise convert the value from its
    type into a unicode string.

    :param value: value to be returned as unicode
    :returns: value as unicode
    :raises UnicodeDecodeError: for invalid UTF-8 encoding
    """
    if isinstance(value, bytes):
        try:
            return _utf8_decoder(value)[0]
        except UnicodeDecodeError:
            # NOTE(lbragstad): We could be dealing with a UUID in byte form,
            # which some LDAP implementations use.
            uuid_byte_string_length = 16
            if len(value) == uuid_byte_string_length:
                return str(uuid.UUID(bytes_le=value))
            else:
                raise
    return str(value)


def py2ldap(val):
    """Type convert a Python value to a type accepted by LDAP (unicode).

    The LDAP API only accepts strings for values therefore convert
    the value's type to a unicode string. A subsequent type conversion
    will encode the unicode as UTF-8 as required by the python-ldap API,
    but for now we just want a string representation of the value.

    :param val: The value to convert to a LDAP string representation
    :returns: unicode string representation of value.
    """
    if isinstance(val, bool):
        return u'TRUE' if val else u'FALSE'
    else:
        return str(val)


def enabled2py(val):
    """Similar to ldap2py, only useful for the enabled attribute."""
    try:
        return LDAP_VALUES[val]
    except KeyError:  # nosec
        # It wasn't a boolean value, will try as an int instead.
        pass
    try:
        return int(val)
    except ValueError:  # nosec
        # It wasn't an int either, will try as utf8 instead.
        pass
    return utf8_decode(val)


def ldap2py(val):
    """Convert an LDAP formatted value to Python type used by OpenStack.

    Virtually all LDAP values are stored as UTF-8 encoded strings.
    OpenStack prefers values which are unicode friendly.

    :param val: LDAP formatted value
    :returns: val converted to preferred Python type
    """
    return utf8_decode(val)


def convert_ldap_result(ldap_result):
    """Convert LDAP search result to Python types used by OpenStack.

    Each result tuple is of the form (dn, attrs), where dn is a string
    containing the DN (distinguished name) of the entry, and attrs is
    a dictionary containing the attributes associated with the
    entry. The keys of attrs are strings, and the associated values
    are lists of strings.

    OpenStack wants to use Python types of its choosing. Strings will
    be unicode, truth values boolean, whole numbers int's, etc. DN's are
    represented as text in python-ldap by default for Python 3 and when
    bytes_mode=False for Python 2, and therefore do not require decoding.

    :param ldap_result: LDAP search result
    :returns: list of 2-tuples containing (dn, attrs) where dn is unicode
              and attrs is a dict whose values are type converted to
              OpenStack preferred types.
    """
    py_result = []
    at_least_one_referral = False
    for dn, attrs in ldap_result:
        ldap_attrs = {}
        if dn is None:
            # this is a Referral object, rather than an Entry object
            at_least_one_referral = True
            continue

        for kind, values in attrs.items():
            try:
                val2py = enabled2py if kind == 'enabled' else ldap2py
                ldap_attrs[kind] = [val2py(x) for x in values]
            except UnicodeDecodeError:
                LOG.debug('Unable to decode value for attribute %s', kind)
        py_result.append((dn, ldap_attrs))
    if at_least_one_referral:
        LOG.debug('Referrals were returned and ignored. Enable referral '
                  'chasing in keystone.conf via [ldap] chase_referrals')

    return py_result


def safe_iter(attrs):
    if attrs is None:
        return
    elif isinstance(attrs, list):
        for e in attrs:
            yield e
    else:
        yield attrs


def parse_deref(opt):
    try:
        return LDAP_DEREF[opt]
    except KeyError:
        raise ValueError(_('Invalid LDAP deref option: %(option)s. '
                           'Choose one of: %(options)s') %
                         {'option': opt,
                          'options': ', '.join(LDAP_DEREF.keys()), })


def parse_tls_cert(opt):
    try:
        return LDAP_TLS_CERTS[opt]
    except KeyError:
        raise ValueError(_(
            'Invalid LDAP TLS certs option: %(option)s. '
            'Choose one of: %(options)s') % {
                'option': opt,
                'options': ', '.join(LDAP_TLS_CERTS.keys())})


def ldap_scope(scope):
    try:
        return LDAP_SCOPES[scope]
    except KeyError:
        raise ValueError(
            _('Invalid LDAP scope: %(scope)s. Choose one of: %(options)s') % {
                'scope': scope,
                'options': ', '.join(LDAP_SCOPES.keys())})


def prep_case_insensitive(value):
    """Prepare a string for case-insensitive comparison.

    This is defined in RFC4518. For simplicity, all this function does is
    lowercase all the characters, strip leading and trailing whitespace,
    and compress sequences of spaces to a single space.
    """
    value = re.sub(r'\s+', ' ', value.strip().lower())
    return value


def is_ava_value_equal(attribute_type, val1, val2):
    """Return True if and only if the AVAs are equal.

    When comparing AVAs, the equality matching rule for the attribute type
    should be taken into consideration. For simplicity, this implementation
    does a case-insensitive comparison.

    Note that this function uses prep_case_insenstive so the limitations of
    that function apply here.

    """
    return prep_case_insensitive(val1) == prep_case_insensitive(val2)


def is_rdn_equal(rdn1, rdn2):
    """Return True if and only if the RDNs are equal.

    * RDNs must have the same number of AVAs.
    * Each AVA of the RDNs must be the equal for the same attribute type. The
      order isn't significant. Note that an attribute type will only be in one
      AVA in an RDN, otherwise the DN wouldn't be valid.
    * Attribute types aren't case sensitive. Note that attribute type
      comparison is more complicated than implemented. This function only
      compares case-insentive. The code should handle multiple names for an
      attribute type (e.g., cn, commonName, and 2.5.4.3 are the same).

    Note that this function uses is_ava_value_equal to compare AVAs so the
    limitations of that function apply here.

    """
    if len(rdn1) != len(rdn2):
        return False

    for attr_type_1, val1, dummy in rdn1:
        found = False
        for attr_type_2, val2, dummy in rdn2:
            if attr_type_1.lower() != attr_type_2.lower():
                continue

            found = True
            if not is_ava_value_equal(attr_type_1, val1, val2):
                return False
            break
        if not found:
            return False

    return True


def is_dn_equal(dn1, dn2):
    """Return True if and only if the DNs are equal.

    Two DNs are equal if they've got the same number of RDNs and if the RDNs
    are the same at each position. See RFC4517.

    Note that this function uses is_rdn_equal to compare RDNs so the
    limitations of that function apply here.

    :param dn1: Either a string DN or a DN parsed by ldap.dn.str2dn.
    :param dn2: Either a string DN or a DN parsed by ldap.dn.str2dn.

    """
    if not isinstance(dn1, list):
        dn1 = ldap.dn.str2dn(dn1)
    if not isinstance(dn2, list):
        dn2 = ldap.dn.str2dn(dn2)

    if len(dn1) != len(dn2):
        return False

    for rdn1, rdn2 in zip(dn1, dn2):
        if not is_rdn_equal(rdn1, rdn2):
            return False
    return True


def dn_startswith(descendant_dn, dn):
    """Return True if and only if the descendant_dn is under the dn.

    :param descendant_dn: Either a string DN or a DN parsed by ldap.dn.str2dn.
    :param dn: Either a string DN or a DN parsed by ldap.dn.str2dn.

    """
    if not isinstance(descendant_dn, list):
        descendant_dn = ldap.dn.str2dn(descendant_dn)
    if not isinstance(dn, list):
        dn = ldap.dn.str2dn(dn)

    if len(descendant_dn) <= len(dn):
        return False

    # Use the last len(dn) RDNs.
    return is_dn_equal(descendant_dn[-len(dn):], dn)


class LDAPHandler(object, metaclass=abc.ABCMeta):
    """Abstract class which defines methods for a LDAP API provider.

    Native Keystone values cannot be passed directly into and from the
    python-ldap API. Type conversion must occur at the LDAP API
    boundary, examples of type conversions are:

        * booleans map to the strings 'TRUE' and 'FALSE'

        * integer values map to their string representation.

        * unicode strings are encoded in UTF-8

    Note, in python-ldap some fields (DNs, RDNs, attribute names, queries)
    are represented as text (str on Python 3, unicode on Python 2 when
    bytes_mode=False). For more details see:
    http://www.python-ldap.org/en/latest/bytes_mode.html#bytes-mode

    In addition to handling type conversions at the API boundary we
    have the requirement to support more than one LDAP API
    provider. Currently we have:

        * python-ldap, this is the standard LDAP API for Python, it
          requires access to a live LDAP server.

        * Fake LDAP which emulates python-ldap. This is used for
          testing without requiring a live LDAP server.

    To support these requirements we need a layer that performs type
    conversions and then calls another LDAP API which is configurable
    (e.g. either python-ldap or the fake emulation).

    We have an additional constraint at the time of this writing due to
    limitations in the logging module. The logging module is not
    capable of accepting UTF-8 encoded strings, it will throw an
    encoding exception. Therefore all logging MUST be performed prior
    to UTF-8 conversion. This means no logging can be performed in the
    ldap APIs that implement the python-ldap API because those APIs
    are defined to accept only UTF-8 strings. Thus the layer which
    performs type conversions must also do the logging. We do the type
    conversions in two steps, once to convert all Python types to
    unicode strings, then log, then convert the unicode strings to
    UTF-8.

    There are a variety of ways one could accomplish this, we elect to
    use a chaining technique whereby instances of this class simply
    call the next member in the chain via the "conn" attribute. The
    chain is constructed by passing in an existing instance of this
    class as the conn attribute when the class is instantiated.

    Here is a brief explanation of why other possible approaches were
    not used:

        subclassing

            To perform the wrapping operations in the correct order
            the type conversion class would have to subclass each of
            the API providers. This is awkward, doubles the number of
            classes, and does not scale well. It requires the type
            conversion class to be aware of all possible API
            providers.

        decorators

            Decorators provide an elegant solution to wrap methods and
            would be an ideal way to perform type conversions before
            calling the wrapped function and then converting the
            values returned from the wrapped function. However
            decorators need to be aware of the method signature, it
            has to know what input parameters need conversion and how
            to convert the result. For an API like python-ldap which
            has a large number of different method signatures it would
            require a large number of specialized
            decorators. Experience has shown it's very easy to apply
            the wrong decorator due to the inherent complexity and
            tendency to cut-n-paste code. Another option is to
            parameterize the decorator to make it "smart". Experience
            has shown such decorators become insanely complicated and
            difficult to understand and debug. Also decorators tend to
            hide what's really going on when a method is called, the
            operations being performed are not visible when looking at
            the implemation of a decorated method, this too experience
            has shown leads to mistakes.

    Chaining simplifies both wrapping to perform type conversion as
    well as the substitution of alternative API providers. One simply
    creates a new instance of the API interface and insert it at the
    front of the chain. Type conversions are explicit and obvious.

    If a new method needs to be added to the API interface one adds it
    to the abstract class definition. Should one miss adding the new
    method to any derivations of the abstract class the code will fail
    to load and run making it impossible to forget updating all the
    derived classes.

    """

    def __init__(self, conn=None):
        self.conn = conn

    @abc.abstractmethod
    def connect(self, url, page_size=0, alias_dereferencing=None,
                use_tls=False, tls_cacertfile=None, tls_cacertdir=None,
                tls_req_cert=ldap.OPT_X_TLS_DEMAND, chase_referrals=None,
                debug_level=None, conn_timeout=None, use_pool=None,
                pool_size=None, pool_retry_max=None, pool_retry_delay=None,
                pool_conn_timeout=None, pool_conn_lifetime=None):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def set_option(self, option, invalue):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def get_option(self, option):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def simple_bind_s(self, who='', cred='',
                      serverctrls=None, clientctrls=None):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def unbind_s(self):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def add_s(self, dn, modlist):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def search_s(self, base, scope,
                 filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def search_ext(self, base, scope,
                   filterstr='(objectClass=*)', attrlist=None, attrsonly=0,
                   serverctrls=None, clientctrls=None,
                   timeout=-1, sizelimit=0):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def result3(self, msgid=ldap.RES_ANY, all=1, timeout=None,
                resp_ctrl_classes=None):
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def modify_s(self, dn, modlist):
        raise exception.NotImplemented()  # pragma: no cover


class PythonLDAPHandler(LDAPHandler):
    """LDAPHandler implementation which calls the python-ldap API.

    Note, the python-ldap API requires all string attribute values to be UTF-8
    encoded.

    Note, in python-ldap some fields (DNs, RDNs, attribute names, queries)
    are represented as text (str on Python 3, unicode on Python 2 when
    bytes_mode=False). For more details see:
    http://www.python-ldap.org/en/latest/bytes_mode.html#bytes-mode

    The KeystoneLDAPHandler enforces this prior to invoking the methods in this
    class.

    """

    def connect(self, url, page_size=0, alias_dereferencing=None,
                use_tls=False, tls_cacertfile=None, tls_cacertdir=None,
                tls_req_cert=ldap.OPT_X_TLS_DEMAND, chase_referrals=None,
                debug_level=None, conn_timeout=None, use_pool=None,
                pool_size=None, pool_retry_max=None, pool_retry_delay=None,
                pool_conn_timeout=None, pool_conn_lifetime=None):

        _common_ldap_initialization(url=url,
                                    use_tls=use_tls,
                                    tls_cacertfile=tls_cacertfile,
                                    tls_cacertdir=tls_cacertdir,
                                    tls_req_cert=tls_req_cert,
                                    debug_level=debug_level,
                                    timeout=conn_timeout)

        self.conn = ldap.initialize(url)
        self.conn.protocol_version = ldap.VERSION3

        if alias_dereferencing is not None:
            self.conn.set_option(ldap.OPT_DEREF, alias_dereferencing)
        self.page_size = page_size

        if use_tls:
            self.conn.start_tls_s()

        if chase_referrals is not None:
            self.conn.set_option(ldap.OPT_REFERRALS, int(chase_referrals))

    def set_option(self, option, invalue):
        return self.conn.set_option(option, invalue)

    def get_option(self, option):
        return self.conn.get_option(option)

    def simple_bind_s(self, who='', cred='',
                      serverctrls=None, clientctrls=None):
        return self.conn.simple_bind_s(who, cred, serverctrls, clientctrls)

    def unbind_s(self):
        return self.conn.unbind_s()

    def add_s(self, dn, modlist):
        return self.conn.add_s(dn, modlist)

    def search_s(self, base, scope,
                 filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        return self.conn.search_s(base, scope, filterstr,
                                  attrlist, attrsonly)

    def search_ext(self, base, scope,
                   filterstr='(objectClass=*)', attrlist=None, attrsonly=0,
                   serverctrls=None, clientctrls=None,
                   timeout=-1, sizelimit=0):
        return self.conn.search_ext(base, scope,
                                    filterstr, attrlist, attrsonly,
                                    serverctrls, clientctrls,
                                    timeout, sizelimit)

    def result3(self, msgid=ldap.RES_ANY, all=1, timeout=None,
                resp_ctrl_classes=None):
        # The resp_ctrl_classes parameter is a recent addition to the
        # API. It defaults to None. We do not anticipate using it.
        # To run with older versions of python-ldap we do not pass it.
        return self.conn.result3(msgid, all, timeout)

    def modify_s(self, dn, modlist):
        return self.conn.modify_s(dn, modlist)


def _common_ldap_initialization(url, use_tls=False, tls_cacertfile=None,
                                tls_cacertdir=None, tls_req_cert=None,
                                debug_level=None, timeout=None):
    """LDAP initialization for PythonLDAPHandler and PooledLDAPHandler."""
    LOG.debug('LDAP init: url=%s', url)
    LOG.debug('LDAP init: use_tls=%s tls_cacertfile=%s tls_cacertdir=%s '
              'tls_req_cert=%s tls_avail=%s',
              use_tls, tls_cacertfile, tls_cacertdir,
              tls_req_cert, ldap.TLS_AVAIL)

    if debug_level is not None:
        ldap.set_option(ldap.OPT_DEBUG_LEVEL, debug_level)

    using_ldaps = url.lower().startswith("ldaps")

    if timeout is not None and timeout > 0:
        # set network connection timeout
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, timeout)

    if use_tls and using_ldaps:
        raise AssertionError(_('Invalid TLS / LDAPS combination'))

    # The certificate trust options apply for both LDAPS and TLS.
    if use_tls or using_ldaps:
        if not ldap.TLS_AVAIL:
            raise ValueError(_('Invalid LDAP TLS_AVAIL option: %s. TLS '
                               'not available') % ldap.TLS_AVAIL)
        if tls_cacertfile:
            # NOTE(topol)
            # python ldap TLS does not verify CACERTFILE or CACERTDIR
            # so we add some extra simple sanity check verification
            # Also, setting these values globally (i.e. on the ldap object)
            # works but these values are ignored when setting them on the
            # connection
            if not os.path.isfile(tls_cacertfile):
                raise IOError(_("tls_cacertfile %s not found "
                                "or is not a file") %
                              tls_cacertfile)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, tls_cacertfile)
        elif tls_cacertdir:
            # NOTE(topol)
            # python ldap TLS does not verify CACERTFILE or CACERTDIR
            # so we add some extra simple sanity check verification
            # Also, setting these values globally (i.e. on the ldap object)
            # works but these values are ignored when setting them on the
            # connection
            if not os.path.isdir(tls_cacertdir):
                raise IOError(_("tls_cacertdir %s not found "
                                "or is not a directory") %
                              tls_cacertdir)
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, tls_cacertdir)
        if tls_req_cert in list(LDAP_TLS_CERTS.values()):
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, tls_req_cert)
        else:
            LOG.debug('LDAP TLS: invalid TLS_REQUIRE_CERT Option=%s',
                      tls_req_cert)


class AsynchronousMessage(object):
    """A container for handling asynchronous LDAP responses.

    Some LDAP APIs, like `search_ext`, are asynchronous and return a message ID
    when the server successfully initiates the operation. Clients can use this
    message ID and the original connection to make the request to fetch the
    results using `result3`.

    This object holds the message ID, the original connection, and a callable
    weak reference Finalizer that cleans up context managers specific to the
    connection associated to the message ID.

    :param message_id: The message identifier (str).
    :param connection: The connection associated with the message identifier
                       (ldappool.StateConnector).

    The `clean` attribute is a callable that cleans up the context manager used
    to create or return the connection object (weakref.finalize).

    """

    def __init__(self, message_id, connection, context_manager):
        self.id = message_id
        self.connection = connection
        self.clean = weakref.finalize(
            self, self._cleanup_connection_context_manager, context_manager
        )

    def _cleanup_connection_context_manager(self, context_manager):
        context_manager.__exit__(None, None, None)


def use_conn_pool(func):
    """Use this only for connection pool specific ldap API.

    This adds connection object to decorated API as next argument after self.

    """
    def wrapper(self, *args, **kwargs):
        # assert isinstance(self, PooledLDAPHandler)
        with self._get_pool_connection() as conn:
            self._apply_options(conn)
            return func(self, conn, *args, **kwargs)
    return wrapper


class PooledLDAPHandler(LDAPHandler):
    """LDAPHandler implementation which uses pooled connection manager.

    Pool specific configuration is defined in [ldap] section.
    All other LDAP configuration is still used from [ldap] section

    Keystone LDAP authentication logic authenticates an end user using its DN
    and password via LDAP bind to establish supplied password is correct.
    This can fill up the pool quickly (as pool re-uses existing connection
    based on its bind data) and would not leave space in pool for connection
    re-use for other LDAP operations.
    Now a separate pool can be established for those requests when related flag
    'use_auth_pool' is enabled. That pool can have its own size and
    connection lifetime. Other pool attributes are shared between those pools.
    If 'use_pool' is disabled, then 'use_auth_pool' does not matter.
    If 'use_auth_pool' is not enabled, then connection pooling is not used for
    those LDAP operations.

    Note, the python-ldap API requires all string attribute values to be UTF-8
    encoded. The KeystoneLDAPHandler enforces this prior to invoking the
    methods in this class.

    Note, in python-ldap some fields (DNs, RDNs, attribute names, queries)
    are represented as text (str on Python 3, unicode on Python 2 when
    bytes_mode=False). For more details see:
    http://www.python-ldap.org/en/latest/bytes_mode.html#bytes-mode

    """

    # Added here to allow override for testing
    Connector = ldappool.StateConnector
    auth_pool_prefix = 'auth_pool_'

    connection_pools = {}  # static connector pool dict

    def __init__(self, conn=None, use_auth_pool=False):
        super(PooledLDAPHandler, self).__init__(conn=conn)
        self.who = ''
        self.cred = ''
        self.conn_options = {}  # connection specific options
        self.page_size = None
        self.use_auth_pool = use_auth_pool
        self.conn_pool = None

    def connect(self, url, page_size=0, alias_dereferencing=None,
                use_tls=False, tls_cacertfile=None, tls_cacertdir=None,
                tls_req_cert=ldap.OPT_X_TLS_DEMAND, chase_referrals=None,
                debug_level=None, conn_timeout=None, use_pool=None,
                pool_size=None, pool_retry_max=None, pool_retry_delay=None,
                pool_conn_timeout=None, pool_conn_lifetime=None):

        _common_ldap_initialization(url=url,
                                    use_tls=use_tls,
                                    tls_cacertfile=tls_cacertfile,
                                    tls_cacertdir=tls_cacertdir,
                                    tls_req_cert=tls_req_cert,
                                    debug_level=debug_level,
                                    timeout=pool_conn_timeout)

        self.page_size = page_size

        # Following two options are not added in common initialization as they
        # need to follow a sequence in PythonLDAPHandler code.
        if alias_dereferencing is not None:
            self.set_option(ldap.OPT_DEREF, alias_dereferencing)
        if chase_referrals is not None:
            self.set_option(ldap.OPT_REFERRALS, int(chase_referrals))

        if self.use_auth_pool:  # separate pool when use_auth_pool enabled
            pool_url = self.auth_pool_prefix + url
        else:
            pool_url = url
        try:
            self.conn_pool = self.connection_pools[pool_url]
        except KeyError:
            self.conn_pool = ldappool.ConnectionManager(
                url,
                size=pool_size,
                retry_max=pool_retry_max,
                retry_delay=pool_retry_delay,
                timeout=pool_conn_timeout,
                connector_cls=self.Connector,
                use_tls=use_tls,
                max_lifetime=pool_conn_lifetime)
            self.connection_pools[pool_url] = self.conn_pool

    def set_option(self, option, invalue):
        self.conn_options[option] = invalue

    def get_option(self, option):
        value = self.conn_options.get(option)
        # if option was not specified explicitly, then use connection default
        # value for that option if there.
        if value is None:
            with self._get_pool_connection() as conn:
                value = conn.get_option(option)
        return value

    def _apply_options(self, conn):
        # if connection has a lifetime, then it already has options specified
        if conn.get_lifetime() > 30:
            return
        for option, invalue in self.conn_options.items():
            conn.set_option(option, invalue)

    def _get_pool_connection(self):
        return self.conn_pool.connection(self.who, self.cred)

    def simple_bind_s(self, who='', cred='',
                      serverctrls=None, clientctrls=None):
        # Not using use_conn_pool decorator here as this API takes cred as
        # input.
        self.who = who
        self.cred = cred
        with self._get_pool_connection() as conn:
            self._apply_options(conn)

    def unbind_s(self):
        # After connection generator is done `with` statement execution block
        # connection is always released via finally block in ldappool.
        # So this unbind is a no op.
        pass

    @use_conn_pool
    def add_s(self, conn, dn, modlist):
        return conn.add_s(dn, modlist)

    @use_conn_pool
    def search_s(self, conn, base, scope,
                 filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        return conn.search_s(base, scope, filterstr, attrlist,
                             attrsonly)

    def search_ext(self, base, scope,
                   filterstr='(objectClass=*)', attrlist=None, attrsonly=0,
                   serverctrls=None, clientctrls=None,
                   timeout=-1, sizelimit=0):
        """Return an AsynchronousMessage instance, it asynchronous API.

        The AsynchronousMessage instance can be safely used in a call to
        `result3()`.

        To work with `result3()` API in predictable manner, the same LDAP
        connection is needed which originally provided the `msgid`. So, this
        method wraps the existing connection and `msgid` in a new
        `AsynchronousMessage` instance. The connection associated with
        `search_ext()` is released after `result3()` fetches the data
        associated with `msgid`.

        """
        conn_ctxt = self._get_pool_connection()
        conn = conn_ctxt.__enter__()
        try:
            msgid = conn.search_ext(base, scope,
                                    filterstr, attrlist, attrsonly,
                                    serverctrls, clientctrls,
                                    timeout, sizelimit)
        except Exception:
            conn_ctxt.__exit__(*sys.exc_info())
            raise
        return AsynchronousMessage(msgid, conn, conn_ctxt)

    def result3(self, message, all=1, timeout=None,
                resp_ctrl_classes=None):
        """Wait for and return the result to an asynchronous message.

        This method returns the result of an operation previously initiated by
        one of the LDAP asynchronous operation routines (e.g., `search_ext()`).
        The `search_ext()` method in python-ldap returns an invocation
        identifier, or a message ID, upon successful initiation of the
        operation by the LDAP server.

        The `message` is expected to be instance of class
        `AsynchronousMessage`, which contains the message ID and the connection
        used to make the original request.

        The connection and context manager associated with `search_ext()` are
        cleaned up when message.clean() is called.

        """
        results = message.connection.result3(message.id, all, timeout)

        # Now that we have the results from the LDAP server for the message, we
        # don't need the the context manager used to create the connection.
        message.clean()

        return results

    @use_conn_pool
    def modify_s(self, conn, dn, modlist):
        return conn.modify_s(dn, modlist)


class KeystoneLDAPHandler(LDAPHandler):
    """Convert data types and perform logging.

    This LDAP interface wraps the python-ldap based interfaces. The
    python-ldap interfaces require string values encoded in UTF-8 with
    the exception of [1]. The OpenStack logging framework at the time
    of this writing is not capable of accepting strings encoded in
    UTF-8, the log functions will throw decoding errors if a non-ascii
    character appears in a string.

    [1] In python-ldap, some fields (DNs, RDNs, attribute names,
    queries) are represented as text (str on Python 3, unicode on
    Python 2 when bytes_mode=False). For more details see:
    http://www.python-ldap.org/en/latest/bytes_mode.html#bytes-mode

    Prior to the call Python data types are converted to a string
    representation as required by the LDAP APIs.

    Then logging is performed so we can track what is being
    sent/received from LDAP. Also the logging filters security
    sensitive items (i.e. passwords).

    Then the string values are encoded into UTF-8.

    Then the LDAP API entry point is invoked.

    Data returned from the LDAP call is converted back from UTF-8
    encoded strings into the Python data type used internally in
    OpenStack.

    """

    def __init__(self, conn=None):
        super(KeystoneLDAPHandler, self).__init__(conn=conn)
        self.page_size = 0

    def __enter__(self):
        """Enter runtime context."""
        return self

    def _disable_paging(self):
        # Disable the pagination from now on
        self.page_size = 0

    def connect(self, url, page_size=0, alias_dereferencing=None,
                use_tls=False, tls_cacertfile=None, tls_cacertdir=None,
                tls_req_cert=ldap.OPT_X_TLS_DEMAND, chase_referrals=None,
                debug_level=None, conn_timeout=None, use_pool=None,
                pool_size=None, pool_retry_max=None, pool_retry_delay=None,
                pool_conn_timeout=None, pool_conn_lifetime=None):
        self.page_size = page_size
        return self.conn.connect(url, page_size, alias_dereferencing,
                                 use_tls, tls_cacertfile, tls_cacertdir,
                                 tls_req_cert, chase_referrals,
                                 debug_level=debug_level,
                                 conn_timeout=conn_timeout,
                                 use_pool=use_pool,
                                 pool_size=pool_size,
                                 pool_retry_max=pool_retry_max,
                                 pool_retry_delay=pool_retry_delay,
                                 pool_conn_timeout=pool_conn_timeout,
                                 pool_conn_lifetime=pool_conn_lifetime)

    def set_option(self, option, invalue):
        return self.conn.set_option(option, invalue)

    def get_option(self, option):
        return self.conn.get_option(option)

    def simple_bind_s(self, who='', cred='',
                      serverctrls=None, clientctrls=None):
        LOG.debug('LDAP bind: who=%s', who)
        return self.conn.simple_bind_s(who, cred,
                                       serverctrls=serverctrls,
                                       clientctrls=clientctrls)

    def unbind_s(self):
        LOG.debug('LDAP unbind')
        return self.conn.unbind_s()

    def add_s(self, dn, modlist):
        ldap_attrs = [(kind, [py2ldap(x) for x in safe_iter(values)])
                      for kind, values in modlist]
        logging_attrs = [(kind, values
                         if kind != 'userPassword'
                         else ['****'])
                         for kind, values in ldap_attrs]
        LOG.debug('LDAP add: dn=%s attrs=%s',
                  dn, logging_attrs)
        ldap_attrs_utf8 = [(kind, [utf8_encode(x) for x in safe_iter(values)])
                           for kind, values in ldap_attrs]
        return self.conn.add_s(dn, ldap_attrs_utf8)

    def search_s(self, base, scope,
                 filterstr='(objectClass=*)', attrlist=None, attrsonly=0):
        # NOTE(morganfainberg): Remove "None" singletons from this list, which
        # allows us to set mapped attributes to "None" as defaults in config.
        # Without this filtering, the ldap query would raise a TypeError since
        # attrlist is expected to be an iterable of strings.
        if attrlist is not None:
            attrlist = [attr for attr in attrlist if attr is not None]
        LOG.debug('LDAP search: base=%s scope=%s filterstr=%s '
                  'attrs=%s attrsonly=%s',
                  base, scope, filterstr, attrlist, attrsonly)
        if self.page_size:
            ldap_result = self._paged_search_s(base, scope,
                                               filterstr, attrlist)
        else:
            try:
                ldap_result = self.conn.search_s(base, scope, filterstr,
                                                 attrlist, attrsonly)
            except ldap.SIZELIMIT_EXCEEDED:
                raise exception.LDAPSizeLimitExceeded()

        py_result = convert_ldap_result(ldap_result)

        return py_result

    def search_ext(self, base, scope,
                   filterstr='(objectClass=*)', attrlist=None, attrsonly=0,
                   serverctrls=None, clientctrls=None,
                   timeout=-1, sizelimit=0):
        if attrlist is not None:
            attrlist = [attr for attr in attrlist if attr is not None]
        LOG.debug('LDAP search_ext: base=%s scope=%s filterstr=%s '
                  'attrs=%s attrsonly=%s '
                  'serverctrls=%s clientctrls=%s timeout=%s sizelimit=%s',
                  base, scope, filterstr, attrlist, attrsonly,
                  serverctrls, clientctrls, timeout, sizelimit)
        return self.conn.search_ext(base, scope,
                                    filterstr, attrlist, attrsonly,
                                    serverctrls, clientctrls,
                                    timeout, sizelimit)

    def _paged_search_s(self, base, scope, filterstr, attrlist=None):
        res = []
        use_old_paging_api = False
        # The API for the simple paged results control changed between
        # python-ldap 2.3 and 2.4.  We need to detect the capabilities
        # of the python-ldap version we are using.
        if hasattr(ldap, 'LDAP_CONTROL_PAGE_OID'):
            use_old_paging_api = True
            lc = ldap.controls.SimplePagedResultsControl(
                controlType=ldap.LDAP_CONTROL_PAGE_OID,
                criticality=True,
                controlValue=(self.page_size, ''))
            page_ctrl_oid = ldap.LDAP_CONTROL_PAGE_OID
        else:
            lc = ldap.controls.libldap.SimplePagedResultsControl(
                criticality=True,
                size=self.page_size,
                cookie='')
            page_ctrl_oid = ldap.controls.SimplePagedResultsControl.controlType

        message = self.conn.search_ext(base,
                                       scope,
                                       filterstr,
                                       attrlist,
                                       serverctrls=[lc])
        # Endless loop request pages on ldap server until it has no data
        while True:
            # Request to the ldap server a page with 'page_size' entries
            rtype, rdata, rmsgid, serverctrls = self.conn.result3(message)
            # Receive the data
            res.extend(rdata)
            pctrls = [c for c in serverctrls
                      if c.controlType == page_ctrl_oid]
            if pctrls:
                # LDAP server supports pagination
                if use_old_paging_api:
                    est, cookie = pctrls[0].controlValue
                    lc.controlValue = (self.page_size, cookie)
                else:
                    cookie = lc.cookie = pctrls[0].cookie

                if cookie:
                    # There is more data still on the server
                    # so we request another page
                    message = self.conn.search_ext(base,
                                                   scope,
                                                   filterstr,
                                                   attrlist,
                                                   serverctrls=[lc])
                else:
                    # Exit condition no more data on server
                    break
            else:
                LOG.warning('LDAP Server does not support paging. '
                            'Disable paging in keystone.conf to '
                            'avoid this message.')
                self._disable_paging()
                break
        return res

    def result3(self, msgid=ldap.RES_ANY, all=1, timeout=None,
                resp_ctrl_classes=None):
        ldap_result = self.conn.result3(msgid, all, timeout, resp_ctrl_classes)

        LOG.debug('LDAP result3: msgid=%s all=%s timeout=%s '
                  'resp_ctrl_classes=%s ldap_result=%s',
                  msgid, all, timeout, resp_ctrl_classes, ldap_result)

        # ldap_result returned from result3 is a tuple of
        # (rtype, rdata, rmsgid, serverctrls). We don't need use of these,
        # except rdata.
        rtype, rdata, rmsgid, serverctrls = ldap_result
        py_result = convert_ldap_result(rdata)
        return py_result

    def modify_s(self, dn, modlist):
        ldap_modlist = [
            (op, kind, (None if values is None
                        else [py2ldap(x) for x in safe_iter(values)]))
            for op, kind, values in modlist]

        logging_modlist = [(op, kind, (values if kind != 'userPassword'
                           else ['****']))
                           for op, kind, values in ldap_modlist]
        LOG.debug('LDAP modify: dn=%s modlist=%s',
                  dn, logging_modlist)

        ldap_modlist_utf8 = [
            (op, kind, (None if values is None
                        else [utf8_encode(x) for x in safe_iter(values)]))
            for op, kind, values in ldap_modlist]
        return self.conn.modify_s(dn, ldap_modlist_utf8)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit runtime context, unbind LDAP."""
        self.unbind_s()


_HANDLERS = {}


def register_handler(prefix, handler):
    _HANDLERS[prefix] = handler


def _get_connection(conn_url, use_pool=False, use_auth_pool=False):
    for prefix, handler in _HANDLERS.items():
        if conn_url.startswith(prefix):
            return handler()

    if use_pool:
        return PooledLDAPHandler(use_auth_pool=use_auth_pool)
    else:
        return PythonLDAPHandler()


def filter_entity(entity_ref):
    """Filter out private items in an entity dict.

    :param entity_ref:  the entity dictionary. The 'dn' field will be removed.
        'dn' is used in LDAP, but should not be returned to the user.  This
        value may be modified.

    :returns: entity_ref

    """
    if entity_ref:
        entity_ref.pop('dn', None)
    return entity_ref


class BaseLdap(object):
    DEFAULT_OU = None
    DEFAULT_STRUCTURAL_CLASSES = None
    DEFAULT_ID_ATTR = 'cn'
    DEFAULT_OBJECTCLASS = None
    DEFAULT_FILTER = None
    DEFAULT_EXTRA_ATTR_MAPPING = []
    NotFound = None
    notfound_arg = None
    options_name = None
    model = None
    attribute_options_names = {}
    immutable_attrs = []
    attribute_ignore = []
    tree_dn = None

    def __init__(self, conf):
        self.LDAP_URL = conf.ldap.url
        self.LDAP_USER = conf.ldap.user
        self.LDAP_PASSWORD = conf.ldap.password
        self.LDAP_SCOPE = ldap_scope(conf.ldap.query_scope)
        self.alias_dereferencing = parse_deref(conf.ldap.alias_dereferencing)
        self.page_size = conf.ldap.page_size
        self.use_tls = conf.ldap.use_tls
        self.tls_cacertfile = conf.ldap.tls_cacertfile
        self.tls_cacertdir = conf.ldap.tls_cacertdir
        self.tls_req_cert = parse_tls_cert(conf.ldap.tls_req_cert)
        self.attribute_mapping = {}
        self.chase_referrals = conf.ldap.chase_referrals
        self.debug_level = conf.ldap.debug_level
        self.conn_timeout = conf.ldap.connection_timeout

        # LDAP Pool specific attribute
        self.use_pool = conf.ldap.use_pool
        self.pool_size = conf.ldap.pool_size
        self.pool_retry_max = conf.ldap.pool_retry_max
        self.pool_retry_delay = conf.ldap.pool_retry_delay
        self.pool_conn_timeout = conf.ldap.pool_connection_timeout
        self.pool_conn_lifetime = conf.ldap.pool_connection_lifetime

        # End user authentication pool specific config attributes
        self.use_auth_pool = self.use_pool and conf.ldap.use_auth_pool
        self.auth_pool_size = conf.ldap.auth_pool_size
        self.auth_pool_conn_lifetime = conf.ldap.auth_pool_connection_lifetime

        if self.options_name is not None:
            self.tree_dn = (
                getattr(conf.ldap, '%s_tree_dn' % self.options_name)
                or '%s,%s' % (self.DEFAULT_OU, conf.ldap.suffix))

            idatt = '%s_id_attribute' % self.options_name
            self.id_attr = getattr(conf.ldap, idatt) or self.DEFAULT_ID_ATTR

            objclass = '%s_objectclass' % self.options_name
            self.object_class = (getattr(conf.ldap, objclass)
                                 or self.DEFAULT_OBJECTCLASS)

            for k, v in self.attribute_options_names.items():
                v = '%s_%s_attribute' % (self.options_name, v)
                self.attribute_mapping[k] = getattr(conf.ldap, v)

            attr_mapping_opt = ('%s_additional_attribute_mapping' %
                                self.options_name)
            attr_mapping = (getattr(conf.ldap, attr_mapping_opt)
                            or self.DEFAULT_EXTRA_ATTR_MAPPING)
            self.extra_attr_mapping = self._parse_extra_attrs(attr_mapping)

            ldap_filter = '%s_filter' % self.options_name
            self.ldap_filter = getattr(conf.ldap,
                                       ldap_filter) or self.DEFAULT_FILTER

            member_attribute = '%s_member_attribute' % self.options_name
            self.member_attribute = getattr(conf.ldap, member_attribute, None)

            self.structural_classes = self.DEFAULT_STRUCTURAL_CLASSES

            if self.notfound_arg is None:
                self.notfound_arg = self.options_name + '_id'

            attribute_ignore = '%s_attribute_ignore' % self.options_name
            self.attribute_ignore = getattr(conf.ldap, attribute_ignore)

    def _not_found(self, object_id):
        if self.NotFound is None:
            return exception.NotFound(target=object_id)
        else:
            return self.NotFound(**{self.notfound_arg: object_id})

    @staticmethod
    def _parse_extra_attrs(option_list):
        mapping = {}
        for item in option_list:
            try:
                ldap_attr, attr_map = item.split(':')
            except ValueError:
                LOG.warning(
                    'Invalid additional attribute mapping: "%s". '
                    'Format must be <ldap_attribute>:<keystone_attribute>',
                    item)
                continue
            mapping[ldap_attr] = attr_map
        return mapping

    def get_connection(self, user=None, password=None, end_user_auth=False):
        use_pool = self.use_pool
        pool_size = self.pool_size
        pool_conn_lifetime = self.pool_conn_lifetime

        if end_user_auth:
            if not self.use_auth_pool:
                use_pool = False
            else:
                pool_size = self.auth_pool_size
                pool_conn_lifetime = self.auth_pool_conn_lifetime

        conn = _get_connection(self.LDAP_URL, use_pool,
                               use_auth_pool=end_user_auth)

        conn = KeystoneLDAPHandler(conn=conn)

        # The LDAP server may be down or a connection may not
        # exist. If that is the case, the bind attempt will
        # fail with a server down exception.
        try:
            conn.connect(self.LDAP_URL,
                         page_size=self.page_size,
                         alias_dereferencing=self.alias_dereferencing,
                         use_tls=self.use_tls,
                         tls_cacertfile=self.tls_cacertfile,
                         tls_cacertdir=self.tls_cacertdir,
                         tls_req_cert=self.tls_req_cert,
                         chase_referrals=self.chase_referrals,
                         debug_level=self.debug_level,
                         conn_timeout=self.conn_timeout,
                         use_pool=use_pool,
                         pool_size=pool_size,
                         pool_retry_max=self.pool_retry_max,
                         pool_retry_delay=self.pool_retry_delay,
                         pool_conn_timeout=self.pool_conn_timeout,
                         pool_conn_lifetime=pool_conn_lifetime)

            if user is None:
                user = self.LDAP_USER

            if password is None:
                password = self.LDAP_PASSWORD

            # not all LDAP servers require authentication, so we don't bind
            # if we don't have any user/pass
            if user and password:
                conn.simple_bind_s(user, password)
            else:
                conn.simple_bind_s()

            return conn
        except ldap.INVALID_CREDENTIALS:
            raise exception.LDAPInvalidCredentialsError()
        except ldap.SERVER_DOWN:
            raise exception.LDAPServerConnectionError(
                url=self.LDAP_URL)

    def _id_to_dn_string(self, object_id):
        return u'%s=%s,%s' % (self.id_attr,
                              ldap.dn.escape_dn_chars(
                                  str(object_id)),
                              self.tree_dn)

    def _id_to_dn(self, object_id):
        if self.LDAP_SCOPE == ldap.SCOPE_ONELEVEL:
            return self._id_to_dn_string(object_id)
        with self.get_connection() as conn:
            search_result = conn.search_s(
                self.tree_dn, self.LDAP_SCOPE,
                u'(&(%(id_attr)s=%(id)s)(objectclass=%(objclass)s))' %
                {'id_attr': self.id_attr,
                 'id': ldap.filter.escape_filter_chars(
                     str(object_id)),
                 'objclass': self.object_class},
                attrlist=DN_ONLY)
        if search_result:
            dn, attrs = search_result[0]
            return dn
        else:
            return self._id_to_dn_string(object_id)

    def _dn_to_id(self, dn):
        # Check if the naming attribute in the DN is the same as keystone's
        # configured 'id' attribute'.  If so, extract the ID value from the DN
        if self.id_attr == ldap.dn.str2dn(dn)[0][0][0].lower():
            return ldap.dn.str2dn(dn)[0][0][1]
        else:
            # The 'ID' attribute is NOT in the DN, so we need to perform an
            # LDAP search to look it up from the user entry itself.
            with self.get_connection() as conn:
                search_result = conn.search_s(dn, ldap.SCOPE_BASE)

            if search_result:
                try:
                    id_list = search_result[0][1][self.id_attr]
                except KeyError:
                    message = ('ID attribute %(id_attr)s not found in LDAP '
                               'object %(dn)s.') % ({'id_attr': self.id_attr,
                                                     'dn': search_result})
                    LOG.warning(message)
                    raise exception.NotFound(message=message)
                if len(id_list) > 1:
                    message = ('In order to keep backward compatibility, in '
                               'the case of multivalued ids, we are '
                               'returning the first id %(id_attr)s in the '
                               'DN.') % ({'id_attr': id_list[0]})
                    LOG.warning(message)
                return id_list[0]
            else:
                message = _('DN attribute %(dn)s not found in LDAP') % (
                    {'dn': dn})
                raise exception.NotFound(message=message)

    def _ldap_res_to_model(self, res):
        # LDAP attribute names may be returned in a different case than
        # they are defined in the mapping, so we need to check for keys
        # in a case-insensitive way.  We use the case specified in the
        # mapping for the model to ensure we have a predictable way of
        # retrieving values later.
        lower_res = {k.lower(): v for k, v in res[1].items()}

        id_attrs = lower_res.get(self.id_attr.lower())
        if not id_attrs:
            message = _('ID attribute %(id_attr)s not found in LDAP '
                        'object %(dn)s') % ({'id_attr': self.id_attr,
                                             'dn': res[0]})
            raise exception.NotFound(message=message)
        if len(id_attrs) > 1:
            # FIXME(gyee): if this is a multi-value attribute and it has
            # multiple values, we can't use it as ID. Retain the dn_to_id
            # logic here so it does not potentially break existing
            # deployments. We need to fix our read-write LDAP logic so
            # it does not get the ID from DN.
            message = ('ID attribute %(id_attr)s for LDAP object %(dn)s '
                       'has multiple values and therefore cannot be used '
                       'as an ID. Will get the ID from DN instead') % (
                           {'id_attr': self.id_attr, 'dn': res[0]})
            LOG.warning(message)
            id_val = self._dn_to_id(res[0])
        else:
            id_val = id_attrs[0]
        obj = self.model(id=id_val)

        for k in obj.known_keys:
            if k in self.attribute_ignore:
                continue

            try:
                map_attr = self.attribute_mapping.get(k, k)
                if map_attr is None:
                    # Ignore attributes that are mapped to None.
                    continue

                v = lower_res[map_attr.lower()]
            except KeyError:  # nosec
                # Didn't find the attr, so don't add it.
                pass
            else:
                try:
                    value = v[0]
                except IndexError:
                    value = None

                # NOTE(xek): Some LDAP servers return bytes data type
                # We convert it to string here, so that it is consistent with
                # the other (SQL) backends.
                # Bytes data type caused issues in the past, because it could
                # be cached and then passed into str() method to be used as
                # LDAP filters, which results in an unexpected b'...' prefix.
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        LOG.error("Error decoding value %r (object id %r).",
                                  value, res[0])
                        raise
                obj[k] = value

        return obj

    def affirm_unique(self, values):
        if values.get('name') is not None:
            try:
                self.get_by_name(values['name'])
            except exception.NotFound:  # nosec
                # Didn't find it so it's unique, good.
                pass
            else:
                raise exception.Conflict(type=self.options_name,
                                         details=_('Duplicate name, %s.') %
                                         values['name'])

        if values.get('id') is not None:
            try:
                self.get(values['id'])
            except exception.NotFound:  # nosec
                # Didn't find it, so it's unique, good.
                pass
            else:
                raise exception.Conflict(type=self.options_name,
                                         details=_('Duplicate ID, %s.') %
                                         values['id'])

    def create(self, values):
        self.affirm_unique(values)
        object_classes = self.structural_classes + [self.object_class]
        attrs = [('objectClass', object_classes)]
        for k, v in values.items():
            if k in self.attribute_ignore:
                continue
            if k == 'id':
                # no need to check if v is None as 'id' will always have
                # a value
                attrs.append((self.id_attr, [v]))
            elif v is not None:
                attr_type = self.attribute_mapping.get(k, k)
                if attr_type is not None:
                    attrs.append((attr_type, [v]))
                extra_attrs = [attr for attr, name
                               in self.extra_attr_mapping.items()
                               if name == k]
                for attr in extra_attrs:
                    attrs.append((attr, [v]))

        with self.get_connection() as conn:
            conn.add_s(self._id_to_dn(values['id']), attrs)
        return values

    # NOTE(prashkre): Filter ldap search results on an attribute to ensure
    # that attribute has a value set on ldap. This keeps keystone away
    # from entities that don't have attribute value set on ldap.
    # for e.g. In ldap configuration, if user_name_attribute = personName
    # then it will ignore ldap users who don't have 'personName' attribute
    # value set on user.
    def _filter_ldap_result_by_attr(self, ldap_result, ldap_attr_name):
        attr = self.attribute_mapping[ldap_attr_name]

        # To ensure that ldap attribute value is not empty in ldap config.
        if not attr:
            attr_name = ('%s_%s_attribute' %
                         (self.options_name,
                          self.attribute_options_names[ldap_attr_name]))
            raise ValueError('"%(attr)s" is not a valid value for'
                             ' "%(attr_name)s"' % {'attr': attr,
                                                   'attr_name': attr_name})

        # consider attr = "cn" and
        # ldap_result = [{'uid': ['fake_id1']}, , 'cN': ["name"]}]
        # doing lower case on both user_name_attribute and ldap users
        # attribute
        result = []
        # consider attr = "cn" and
        # ldap_result = [(u'cn=fake1,o=ex_domain', {'uid': ['fake_id1']}),
        #                (u'cn=fake2,o=ex_domain', {'uid': ['fake_id2'],
        #                'cn': ['     ']}),
        #                (u'cn=fake3,o=ex_domain', {'uid': ['fake_id3'],
        #                'cn': ['']}),
        #                (u'cn=fake4,o=ex_domain', {'uid': ['fake_id4'],
        #                'cn': []}),
        #                (u'cn=fake5,o=ex_domain', {'uid': ['fake_id5'],
        #                'cn': ["name"]})]
        for obj in ldap_result:
            # ignore ldap object(user/group entry) which has no attr set
            # in it or whose value is empty list.
            ldap_res_low_keys_dict = {k.lower(): v for k, v in obj[1].items()}
            result_attr_vals = ldap_res_low_keys_dict.get(attr.lower())
            # ignore ldap object whose attr value has empty strings or
            # contains only whitespaces.
            if result_attr_vals:
                if result_attr_vals[0] and result_attr_vals[0].strip():
                    result.append(obj)
        # except {'uid': ['fake_id5'], 'cn': ["name"]}, all entries
        # will be ignored in ldap_result
        return result

    def _ldap_get(self, object_id, ldap_filter=None):
        query = (u'(&(%(id_attr)s=%(id)s)'
                 u'%(filter)s'
                 u'(objectClass=%(object_class)s))'
                 % {'id_attr': self.id_attr,
                    'id': ldap.filter.escape_filter_chars(
                        str(object_id)),
                    'filter': (ldap_filter or self.ldap_filter or ''),
                    'object_class': self.object_class})
        with self.get_connection() as conn:
            try:
                attrs = list(set(([self.id_attr] +
                                  list(self.attribute_mapping.values()) +
                                  list(self.extra_attr_mapping.keys()))))
                res = conn.search_s(self.tree_dn,
                                    self.LDAP_SCOPE,
                                    query,
                                    attrs)
            except ldap.NO_SUCH_OBJECT:
                return None

        # TODO(prashkre): add functional testing for missing name attibute
        # on ldap entities.
        # NOTE(prashkre): Filter ldap search result to keep keystone away from
        # entities that don't have names. We can also do the same by appending
        # a condition '(!(!(self.attribute_mapping.get('name')=*))' to ldap
        # search query but the repsonse time of the query is pretty slow when
        # compared to explicit filtering by 'name' through ldap result.
        try:
            return self._filter_ldap_result_by_attr(res[:1], 'name')[0]
        except IndexError:
            return None

    def _ldap_get_limited(self, base, scope, filterstr, attrlist, sizelimit):
        with self.get_connection() as conn:
            try:
                control = ldap.controls.libldap.SimplePagedResultsControl(
                    criticality=True,
                    size=sizelimit,
                    cookie='')
                msgid = conn.search_ext(base, scope, filterstr, attrlist,
                                        serverctrls=[control])
                rdata = conn.result3(msgid)
                return rdata
            except ldap.NO_SUCH_OBJECT:
                return []

    @driver_hints.truncated
    def _ldap_get_all(self, hints, ldap_filter=None):
        query = u'(&%s(objectClass=%s)(%s=*))' % (
            ldap_filter or self.ldap_filter or '',
            self.object_class,
            self.id_attr)
        sizelimit = 0
        attrs = list(set(([self.id_attr] +
                          list(self.attribute_mapping.values()) +
                          list(self.extra_attr_mapping.keys()))))
        if hints.limit:
            sizelimit = hints.limit['limit']
            res = self._ldap_get_limited(self.tree_dn,
                                         self.LDAP_SCOPE,
                                         query,
                                         attrs,
                                         sizelimit)
        else:
            with self.get_connection() as conn:
                try:
                    res = conn.search_s(self.tree_dn,
                                        self.LDAP_SCOPE,
                                        query,
                                        attrs)
                except ldap.NO_SUCH_OBJECT:
                    return []
        # TODO(prashkre): add functional testing for missing name attribute
        # on ldap entities.
        # NOTE(prashkre): Filter ldap search result to keep keystone away from
        # entities that don't have names. We can also do the same by appending
        # a condition '(!(!(self.attribute_mapping.get('name')=*))' to ldap
        # search query but the repsonse time of the query is pretty slow when
        # compared to explicit filtering by 'name' through ldap result.
        return self._filter_ldap_result_by_attr(res, 'name')

    def _ldap_get_list(self, search_base, scope, query_params=None,
                       attrlist=None):
        query = u'(objectClass=%s)' % self.object_class
        if query_params:

            def calc_filter(attrname, value):
                val_esc = ldap.filter.escape_filter_chars(value)
                return '(%s=%s)' % (attrname, val_esc)

            query = (u'(&%s%s)' %
                     (query, ''.join([calc_filter(k, v) for k, v in
                                      query_params.items()])))
        with self.get_connection() as conn:
            return conn.search_s(search_base, scope, query, attrlist)

    def get(self, object_id, ldap_filter=None):
        res = self._ldap_get(object_id, ldap_filter)
        if res is None:
            raise self._not_found(object_id)
        else:
            return self._ldap_res_to_model(res)

    def get_by_name(self, name, ldap_filter=None):
        query = (u'(%s=%s)' % (self.attribute_mapping['name'],
                               ldap.filter.escape_filter_chars(
                                   str(name))))
        res = self.get_all(query)
        try:
            return res[0]
        except IndexError:
            raise self._not_found(name)

    def get_all(self, ldap_filter=None, hints=None):
        hints = hints or driver_hints.Hints()
        return [self._ldap_res_to_model(x)
                for x in self._ldap_get_all(hints, ldap_filter)]

    def update(self, object_id, values, old_obj=None):
        if old_obj is None:
            old_obj = self.get(object_id)

        modlist = []
        for k, v in values.items():
            if k == 'id':
                # id can't be modified.
                continue

            if k in self.attribute_ignore:

                # Handle 'enabled' specially since can't disable if ignored.
                if k == 'enabled' and (not v):
                    action = _("Disabling an entity where the 'enable' "
                               "attribute is ignored by configuration.")
                    raise exception.ForbiddenAction(action=action)

                continue

            # attribute value has not changed
            if k in old_obj and old_obj[k] == v:
                continue

            if k in self.immutable_attrs:
                msg = (_("Cannot change %(option_name)s %(attr)s") %
                       {'option_name': self.options_name, 'attr': k})
                raise exception.ValidationError(msg)

            if v is None:
                if old_obj.get(k) is not None:
                    modlist.append((ldap.MOD_DELETE,
                                    self.attribute_mapping.get(k, k),
                                    None))
                continue

            current_value = old_obj.get(k)
            if current_value is None:
                op = ldap.MOD_ADD
                modlist.append((op, self.attribute_mapping.get(k, k), [v]))
            elif current_value != v:
                op = ldap.MOD_REPLACE
                modlist.append((op, self.attribute_mapping.get(k, k), [v]))

        if modlist:
            with self.get_connection() as conn:
                try:
                    conn.modify_s(self._id_to_dn(object_id), modlist)
                except ldap.NO_SUCH_OBJECT:
                    raise self._not_found(object_id)

        return self.get(object_id)

    def add_member(self, member_dn, member_list_dn):
        """Add member to the member list.

        :param member_dn: DN of member to be added.
        :param member_list_dn: DN of group to which the
                               member will be added.

        :raises keystone.exception.Conflict: If the user was already a member.
        :raises self.NotFound: If the group entry didn't exist.
        """
        with self.get_connection() as conn:
            try:
                mod = (ldap.MOD_ADD, self.member_attribute, member_dn)
                conn.modify_s(member_list_dn, [mod])
            except ldap.TYPE_OR_VALUE_EXISTS:
                raise exception.Conflict(_('Member %(member)s '
                                           'is already a member'
                                           ' of group %(group)s') % {
                                               'member': member_dn,
                                               'group': member_list_dn})
            except ldap.NO_SUCH_OBJECT:
                raise self._not_found(member_list_dn)

    def filter_query(self, hints, query=None):
        """Apply filtering to a query.

        :param hints: contains the list of filters, which may be None,
                      indicating that there are no filters to be applied.
                      If it's not None, then any filters satisfied here will be
                      removed so that the caller will know if any filters
                      remain to be applied.
        :param query: LDAP query into which to include filters

        :returns query: LDAP query, updated with any filters satisfied

        """
        def build_filter(filter_):
            """Build a filter for the query.

            :param filter_: the dict that describes this filter

            :returns query: LDAP query term to be added

            """
            ldap_attr = self.attribute_mapping[filter_['name']]
            val_esc = ldap.filter.escape_filter_chars(filter_['value'])

            if filter_['case_sensitive']:
                # NOTE(henry-nash): Although dependent on the schema being
                # used, most LDAP attributes are configured with case
                # insensitive matching rules, so we'll leave this to the
                # controller to filter.
                return

            if filter_['name'] == 'enabled':
                # NOTE(henry-nash): Due to the different options for storing
                # the enabled attribute (e,g, emulated or not), for now we
                # don't try and filter this at the driver level - we simply
                # leave the filter to be handled by the controller. It seems
                # unlikley that this will cause a signifcant performance
                # issue.
                return

            # TODO(henry-nash): Currently there are no booleans (other than
            # 'enabled' that is handled above) on which you can filter. If
            # there were, we would need to add special handling here to
            # convert the booleans values to 'TRUE' and 'FALSE'. To do that
            # we would also need to know which filter keys were actually
            # booleans (this is related to bug #1411478).

            if filter_['comparator'] == 'equals':
                query_term = (u'(%(attr)s=%(val)s)'
                              % {'attr': ldap_attr, 'val': val_esc})
            elif filter_['comparator'] == 'contains':
                query_term = (u'(%(attr)s=*%(val)s*)'
                              % {'attr': ldap_attr, 'val': val_esc})
            elif filter_['comparator'] == 'startswith':
                query_term = (u'(%(attr)s=%(val)s*)'
                              % {'attr': ldap_attr, 'val': val_esc})
            elif filter_['comparator'] == 'endswith':
                query_term = (u'(%(attr)s=*%(val)s)'
                              % {'attr': ldap_attr, 'val': val_esc})
            else:
                # It's a filter we don't understand, so let the caller
                # work out if they need to do something with it.
                return

            return query_term

        if query is None:
            # make sure query is a string so the ldap filter is properly
            # constructed from filter_list later
            query = ''

        if hints is None:
            return query

        filter_list = []
        satisfied_filters = []

        for filter_ in hints.filters:
            if filter_['name'] not in self.attribute_mapping:
                continue
            new_filter = build_filter(filter_)
            if new_filter is not None:
                filter_list.append(new_filter)
                satisfied_filters.append(filter_)

        if filter_list:
            query = u'(&%s%s)' % (query, ''.join(filter_list))

        # Remove satisfied filters, then the caller will know remaining filters
        for filter_ in satisfied_filters:
            hints.filters.remove(filter_)

        return query


class EnabledEmuMixIn(BaseLdap):
    """Emulates boolean 'enabled' attribute if turned on.

    Creates a group holding all enabled objects of this class, all missing
    objects are considered disabled.

    Options:

    * $name_enabled_emulation - boolean, on/off
    * $name_enabled_emulation_dn - DN of that group, default is
      cn=enabled_${name}s,${tree_dn}
    * $name_enabled_emulation_use_group_config - boolean, on/off

    Where ${name}s is the plural of self.options_name ('users' or 'tenants'),
    ${tree_dn} is self.tree_dn.
    """

    DEFAULT_GROUP_OBJECTCLASS = 'groupOfNames'
    DEFAULT_MEMBER_ATTRIBUTE = 'member'
    DEFAULT_GROUP_MEMBERS_ARE_IDS = False

    def __init__(self, conf):
        super(EnabledEmuMixIn, self).__init__(conf)
        enabled_emulation = '%s_enabled_emulation' % self.options_name
        self.enabled_emulation = getattr(conf.ldap, enabled_emulation)

        enabled_emulation_dn = '%s_enabled_emulation_dn' % self.options_name
        self.enabled_emulation_dn = getattr(conf.ldap, enabled_emulation_dn)

        use_group_config = ('%s_enabled_emulation_use_group_config' %
                            self.options_name)
        self.use_group_config = getattr(conf.ldap, use_group_config)

        if not self.use_group_config:
            self.member_attribute = self.DEFAULT_MEMBER_ATTRIBUTE
            self.group_objectclass = self.DEFAULT_GROUP_OBJECTCLASS
            self.group_members_are_ids = self.DEFAULT_GROUP_MEMBERS_ARE_IDS
        else:
            self.member_attribute = conf.ldap.group_member_attribute
            self.group_objectclass = conf.ldap.group_objectclass
            self.group_members_are_ids = conf.ldap.group_members_are_ids

        if not self.enabled_emulation_dn:
            naming_attr_name = 'cn'
            naming_attr_value = 'enabled_%ss' % self.options_name
            sub_vals = (naming_attr_name, naming_attr_value, self.tree_dn)
            self.enabled_emulation_dn = '%s=%s,%s' % sub_vals
            naming_attr = (naming_attr_name, [naming_attr_value])
        else:
            # Extract the attribute name and value from the configured DN.
            naming_dn = ldap.dn.str2dn(self.enabled_emulation_dn)
            naming_rdn = naming_dn[0][0]
            naming_attr = (naming_rdn[0],
                           naming_rdn[1])
        self.enabled_emulation_naming_attr = naming_attr

    def _id_to_member_attribute_value(self, object_id):
        """Convert id to value expected by member_attribute."""
        if self.group_members_are_ids:
            return object_id
        return self._id_to_dn(object_id)

    def _is_id_enabled(self, object_id, conn):
        member_attr_val = self._id_to_member_attribute_value(object_id)
        return self._is_member_enabled(member_attr_val, conn)

    def _is_member_enabled(self, member_attr_val, conn):
        query = '(%s=%s)' % (self.member_attribute,
                             ldap.filter.escape_filter_chars(member_attr_val))
        try:
            enabled_value = conn.search_s(self.enabled_emulation_dn,
                                          ldap.SCOPE_BASE,
                                          query, attrlist=DN_ONLY)
        except ldap.NO_SUCH_OBJECT:
            return False
        else:
            return bool(enabled_value)

    def _add_enabled(self, object_id):
        member_attr_val = self._id_to_member_attribute_value(object_id)
        with self.get_connection() as conn:
            if not self._is_member_enabled(member_attr_val, conn):
                modlist = [(ldap.MOD_ADD,
                            self.member_attribute,
                            [member_attr_val])]
                try:
                    conn.modify_s(self.enabled_emulation_dn, modlist)
                except ldap.NO_SUCH_OBJECT:
                    attr_list = [('objectClass', [self.group_objectclass]),
                                 (self.member_attribute,
                                  [member_attr_val]),
                                 self.enabled_emulation_naming_attr]
                    conn.add_s(self.enabled_emulation_dn, attr_list)

    def _remove_enabled(self, object_id):
        member_attr_val = self._id_to_member_attribute_value(object_id)
        modlist = [(ldap.MOD_DELETE,
                    self.member_attribute,
                    [member_attr_val])]
        with self.get_connection() as conn:
            try:
                conn.modify_s(self.enabled_emulation_dn, modlist)
            except (ldap.NO_SUCH_OBJECT, ldap.NO_SUCH_ATTRIBUTE):  # nosec
                # It's already gone, good.
                pass

    def create(self, values):
        if self.enabled_emulation:
            enabled_value = values.pop('enabled', True)
            ref = super(EnabledEmuMixIn, self).create(values)
            if 'enabled' not in self.attribute_ignore:
                if enabled_value:
                    self._add_enabled(ref['id'])
                ref['enabled'] = enabled_value
            return ref
        else:
            return super(EnabledEmuMixIn, self).create(values)

    def get(self, object_id, ldap_filter=None):
        with self.get_connection() as conn:
            ref = super(EnabledEmuMixIn, self).get(object_id, ldap_filter)
            if ('enabled' not in self.attribute_ignore and
                    self.enabled_emulation):
                ref['enabled'] = self._is_id_enabled(object_id, conn)
            return ref

    def get_all(self, ldap_filter=None, hints=None):
        hints = hints or driver_hints.Hints()
        if 'enabled' not in self.attribute_ignore and self.enabled_emulation:
            # had to copy BaseLdap.get_all here to ldap_filter by DN
            obj_list = [self._ldap_res_to_model(x)
                        for x in self._ldap_get_all(hints, ldap_filter)
                        if x[0] != self.enabled_emulation_dn]
            with self.get_connection() as conn:
                for obj_ref in obj_list:
                    obj_ref['enabled'] = self._is_id_enabled(
                        obj_ref['id'], conn)
            return obj_list
        else:
            return super(EnabledEmuMixIn, self).get_all(ldap_filter, hints)

    def update(self, object_id, values, old_obj=None):
        if 'enabled' not in self.attribute_ignore and self.enabled_emulation:
            data = values.copy()
            enabled_value = data.pop('enabled', None)
            ref = super(EnabledEmuMixIn, self).update(object_id, data, old_obj)
            if enabled_value is not None:
                if enabled_value:
                    self._add_enabled(object_id)
                else:
                    self._remove_enabled(object_id)
                ref['enabled'] = enabled_value
            return ref
        else:
            return super(EnabledEmuMixIn, self).update(
                object_id, values, old_obj)
