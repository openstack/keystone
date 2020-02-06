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

import functools
import inspect
import time
import types

from oslo_log import log
import stevedore

from keystone.common import provider_api
from keystone.i18n import _


LOG = log.getLogger(__name__)

if hasattr(inspect, 'getfullargspec'):
    getargspec = inspect.getfullargspec
else:
    getargspec = inspect.getargspec


def response_truncated(f):
    """Truncate the list returned by the wrapped function.

    This is designed to wrap Manager list_{entity} methods to ensure that
    any list limits that are defined are passed to the driver layer.  If a
    hints list is provided, the wrapper will insert the relevant limit into
    the hints so that the underlying driver call can try and honor it. If the
    driver does truncate the response, it will update the 'truncated' attribute
    in the 'limit' entry in the hints list, which enables the caller of this
    function to know if truncation has taken place.  If, however, the driver
    layer is unable to perform truncation, the 'limit' entry is simply left in
    the hints list for the caller to handle.

    A _get_list_limit() method is required to be present in the object class
    hierarchy, which returns the limit for this backend to which we will
    truncate.

    If a hints list is not provided in the arguments of the wrapped call then
    any limits set in the config file are ignored.  This allows internal use
    of such wrapped methods where the entire data set is needed as input for
    the calculations of some other API (e.g. get role assignments for a given
    project).

    """
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if kwargs.get('hints') is None:
            return f(self, *args, **kwargs)

        list_limit = self.driver._get_list_limit()
        if list_limit:
            kwargs['hints'].set_limit(list_limit)
        return f(self, *args, **kwargs)
    return wrapper


def load_driver(namespace, driver_name, *args):
    try:
        driver_manager = stevedore.DriverManager(namespace,
                                                 driver_name,
                                                 invoke_on_load=True,
                                                 invoke_args=args)
        return driver_manager.driver
    except stevedore.exception.NoMatches:
        msg = (_('Unable to find %(name)r driver in %(namespace)r.'))
        raise ImportError(msg % {'name': driver_name, 'namespace': namespace})


class _TraceMeta(type):
    """A metaclass that, in trace mode, will log entry and exit of methods.

    This metaclass automatically wraps all methods on the class when
    instantiated with a decorator that will log entry/exit from a method
    when keystone is run in Trace log level.
    """

    @staticmethod
    def wrapper(__f, __classname):
        __argspec = getargspec(__f)
        __fn_info = '%(module)s.%(classname)s.%(funcname)s' % {
            'module': inspect.getmodule(__f).__name__,
            'classname': __classname,
            'funcname': __f.__name__
        }
        # NOTE(morganfainberg): Omit "cls" and "self" when printing trace logs
        # the index can be calculated at wrap time rather than at runtime.
        if __argspec.args and __argspec.args[0] in ('self', 'cls'):
            __arg_idx = 1
        else:
            __arg_idx = 0

        @functools.wraps(__f)
        def wrapped(*args, **kwargs):
            __exc = None
            __t = time.time()
            __do_trace = LOG.logger.getEffectiveLevel() <= log.TRACE
            __ret_val = None
            try:
                if __do_trace:
                    LOG.trace('CALL => %s', __fn_info)
                __ret_val = __f(*args, **kwargs)
            except Exception as e:  # nosec
                __exc = e
                raise
            finally:
                if __do_trace:
                    __subst = {
                        'run_time': (time.time() - __t),
                        'passed_args': ', '.join([
                            ', '.join([repr(a)
                                       for a in args[__arg_idx:]]),
                            ', '.join(['%(k)s=%(v)r' % {'k': k, 'v': v}
                                       for k, v in kwargs.items()]),
                        ]),
                        'function': __fn_info,
                        'exception': __exc,
                        'ret_val': __ret_val,
                    }
                    if __exc is not None:
                        __msg = ('[%(run_time)ss] %(function)s '
                                 '(%(passed_args)s) => raised '
                                 '%(exception)r')
                    else:
                        # TODO(morganfainberg): find a way to indicate if this
                        # was a cache hit or cache miss.
                        __msg = ('[%(run_time)ss] %(function)s'
                                 '(%(passed_args)s) => %(ret_val)r')
                    LOG.trace(__msg, __subst)
            return __ret_val
        return wrapped

    def __new__(meta, classname, bases, class_dict):
        final_cls_dict = {}
        for attr_name, attr in class_dict.items():
            # NOTE(morganfainberg): only wrap public instances and methods.
            if (isinstance(attr, types.FunctionType) and
                    not attr_name.startswith('_')):
                attr = _TraceMeta.wrapper(attr, classname)
            final_cls_dict[attr_name] = attr
        return type.__new__(meta, classname, bases, final_cls_dict)


class Manager(object, metaclass=_TraceMeta):
    """Base class for intermediary request layer.

    The Manager layer exists to support additional logic that applies to all
    or some of the methods exposed by a service that are not specific to the
    HTTP interface.

    It also provides a stable entry point to dynamic backends.

    An example of a probable use case is logging all the calls.

    """

    driver_namespace = None
    _provides_api = None

    def __init__(self, driver_name):
        if self._provides_api is None:
            raise ValueError('Programming Error: All managers must provide an '
                             'API that can be referenced by other components '
                             'of Keystone.')
        if driver_name is not None:
            self.driver = load_driver(self.driver_namespace, driver_name)
        self.__register_provider_api()

    def __register_provider_api(self):
        provider_api.ProviderAPIs._register_provider_api(
            name=self._provides_api, obj=self)

    def __getattr__(self, name):
        """Forward calls to the underlying driver.

        This method checks for a provider api before forwarding.
        """
        try:
            return getattr(provider_api.ProviderAPIs, name)
        except AttributeError:
            # NOTE(morgan): We didn't find a provider api, move on and
            # forward to the driver as expected.
            pass

        f = getattr(self.driver, name)
        if callable(f):
            # NOTE(dstanek): only if this is callable (class or function)
            # cache this
            setattr(self, name, f)
        return f
