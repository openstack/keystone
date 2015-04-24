# Copyright 2013 OpenStack Foundation
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

import functools
import os

from oslo_log import log


LOG = log.getLogger(__name__)


__all__ = ['Server', 'httplib', 'subprocess']

_configured = False

Server = None
httplib = None
subprocess = None


def configure_once(name):
    """Ensure that environment configuration is only run once.

    If environment is reconfigured in the same way then it is ignored.
    It is an error to attempt to reconfigure environment in a different way.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            global _configured
            if _configured:
                if _configured == name:
                    return
                else:
                    raise SystemError("Environment has already been "
                                      "configured as %s" % _configured)

            LOG.debug("Environment configured as: %s", name)
            _configured = name
            return func(*args, **kwargs)

        return wrapper
    return decorator


@configure_once('eventlet')
def use_eventlet(monkeypatch_thread=None):
    global httplib, subprocess, Server

    # This must be set before the initial import of eventlet because if
    # dnspython is present in your environment then eventlet monkeypatches
    # socket.getaddrinfo() with an implementation which doesn't work for IPv6.
    os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

    import eventlet
    from eventlet.green import httplib as _httplib
    from eventlet.green import subprocess as _subprocess

    from keystone.common.environment import eventlet_server

    if monkeypatch_thread is None:
        monkeypatch_thread = not os.getenv('STANDARD_THREADS')

    # Raise the default from 8192 to accommodate large tokens
    eventlet.wsgi.MAX_HEADER_LINE = 16384

    # NOTE(ldbragst): Explicitly declare what should be monkey patched and
    # what shouldn't. Doing this allows for more readable code when
    # understanding Eventlet in Keystone. The following is a complete list
    # of what is monkey patched instead of passing all=False and then passing
    # module=True to monkey patch a specific module.
    eventlet.patcher.monkey_patch(os=False, select=True, socket=True,
                                  thread=monkeypatch_thread, time=True,
                                  psycopg=False, MySQLdb=False)

    Server = eventlet_server.Server
    httplib = _httplib
    subprocess = _subprocess


@configure_once('stdlib')
def use_stdlib():
    global httplib, subprocess

    import six.moves.http_client as _httplib
    import subprocess as _subprocess

    httplib = _httplib
    subprocess = _subprocess
