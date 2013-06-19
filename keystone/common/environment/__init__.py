import functools
import os

from keystone.common import config
from keystone.common import logging

CONF = config.CONF
LOG = logging.getLogger(__name__)


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

            LOG.info(_("Environment configured as: %s"), name)
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

    eventlet.patcher.monkey_patch(all=False, socket=True, time=True,
                                  thread=monkeypatch_thread)

    Server = eventlet_server.Server
    httplib = _httplib
    subprocess = _subprocess


@configure_once('stdlib')
def use_stdlib():
    global httplib, subprocess

    import httplib as _httplib
    import subprocess as _subprocess

    httplib = _httplib
    subprocess = _subprocess
