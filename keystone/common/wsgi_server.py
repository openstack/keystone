# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2010 OpenStack LLC.
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

import os
import socket
import ssl
import sys

# NOTE(mikal): All of this is because if dnspython is present in your
# environment then eventlet monkeypatches socket.getaddrinfo() with an
# implementation which doesn't work for IPv6. What we're checking here is
# that the magic environment variable was set when the import happened.
if ('eventlet' in sys.modules and
        os.environ.get('EVENTLET_NO_GREENDNS', '').lower() != 'yes'):
    raise ImportError('eventlet imported before '
                      'keystone.common.wsgi_server '
                      '(EVENTLET_NO_GREENDNS env var set to %s)'
                      % os.environ.get('EVENTLET_NO_GREENDNS'))

os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
import eventlet.wsgi

from keystone.common import logging
from keystone.common import wsgi


LOG = logging.getLogger(__name__)


def monkey_patch_eventlet(monkeypatch_thread=None):
    if monkeypatch_thread is None:
        monkeypatch_thread = not os.getenv('STANDARD_THREADS')

    eventlet.patcher.monkey_patch(all=False, socket=True, time=True,
                                  thread=monkeypatch_thread)


class Server(object):
    """Server class to manage multiple WSGI sockets and applications."""

    def __init__(self, application, host=None, port=None, threads=1000):
        self.application = application
        self.host = host or '0.0.0.0'
        self.port = port or 0
        self.pool = eventlet.GreenPool(threads)
        self.socket_info = {}
        self.greenthread = None
        self.do_ssl = False
        self.cert_required = False

    def start(self, key=None, backlog=128):
        """Run a WSGI server with the given application."""
        LOG.debug(_('Starting %(arg0)s on %(host)s:%(port)s') %
                  {'arg0': sys.argv[0],
                   'host': self.host,
                   'port': self.port})

        # TODO(dims): eventlet's green dns/socket module does not actually
        # support IPv6 in getaddrinfo(). We need to get around this in the
        # future or monitor upstream for a fix
        info = socket.getaddrinfo(self.host,
                                  self.port,
                                  socket.AF_UNSPEC,
                                  socket.SOCK_STREAM)[0]
        _socket = eventlet.listen(info[-1],
                                  family=info[0],
                                  backlog=backlog)
        if key:
            self.socket_info[key] = _socket.getsockname()
        # SSL is enabled
        if self.do_ssl:
            if self.cert_required:
                cert_reqs = ssl.CERT_REQUIRED
            else:
                cert_reqs = ssl.CERT_NONE
            sslsocket = eventlet.wrap_ssl(_socket, certfile=self.certfile,
                                          keyfile=self.keyfile,
                                          server_side=True,
                                          cert_reqs=cert_reqs,
                                          ca_certs=self.ca_certs)
            _socket = sslsocket

        self.greenthread = self.pool.spawn(self._run,
                                           self.application,
                                           _socket)

    def set_ssl(self, certfile, keyfile=None, ca_certs=None,
                cert_required=True):
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_certs = ca_certs
        self.cert_required = cert_required
        self.do_ssl = True

    def kill(self):
        if self.greenthread:
            self.greenthread.kill()

    def wait(self):
        """Wait until all servers have completed running."""
        try:
            self.pool.waitall()
        except KeyboardInterrupt:
            pass

    def _run(self, application, socket):
        """Start a WSGI server in a new green thread."""
        log = logging.getLogger('eventlet.wsgi.server')
        try:
            eventlet.wsgi.server(socket, application, custom_pool=self.pool,
                                 log=wsgi.WritableLogger(log))
        except Exception:
            LOG.exception(_('Server error'))
            raise
