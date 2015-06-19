
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

import logging
import os
import socket

from oslo_concurrency import processutils
from oslo_config import cfg
import oslo_i18n
from oslo_service import service
from oslo_service import systemd
import pbr.version


# NOTE(dstanek): i18n.enable_lazy() must be called before
# keystone.i18n._() is called to ensure it has the desired lazy lookup
# behavior. This includes cases, like keystone.exceptions, where
# keystone.i18n._() is called at import time.
oslo_i18n.enable_lazy()


from keystone.common import environment
from keystone.common import utils
from keystone import config
from keystone.i18n import _
from keystone.server import common
from keystone import service as keystone_service


CONF = cfg.CONF


class ServerWrapper(object):
    """Wraps a Server with some launching info & capabilities."""

    def __init__(self, server, workers):
        self.server = server
        self.workers = workers

    def launch_with(self, launcher):
        self.server.listen()
        if self.workers > 1:
            # Use multi-process launcher
            launcher.launch_service(self.server, self.workers)
        else:
            # Use single process launcher
            launcher.launch_service(self.server)


def create_server(conf, name, host, port, workers):
    app = keystone_service.loadapp('config:%s' % conf, name)
    server = environment.Server(app, host=host, port=port,
                                keepalive=CONF.eventlet_server.tcp_keepalive,
                                keepidle=CONF.eventlet_server.tcp_keepidle)
    if CONF.eventlet_server_ssl.enable:
        server.set_ssl(CONF.eventlet_server_ssl.certfile,
                       CONF.eventlet_server_ssl.keyfile,
                       CONF.eventlet_server_ssl.ca_certs,
                       CONF.eventlet_server_ssl.cert_required)
    return name, ServerWrapper(server, workers)


def serve(*servers):
    logging.warning(_('Running keystone via eventlet is deprecated as of Kilo '
                      'in favor of running in a WSGI server (e.g. mod_wsgi). '
                      'Support for keystone under eventlet will be removed in '
                      'the "M"-Release.'))
    if max([server[1].workers for server in servers]) > 1:
        launcher = service.ProcessLauncher(CONF)
    else:
        launcher = service.ServiceLauncher(CONF)

    for name, server in servers:
        try:
            server.launch_with(launcher)
        except socket.error:
            logging.exception(_('Failed to start the %(name)s server') % {
                'name': name})
            raise

    # notify calling process we are ready to serve
    systemd.notify_once()

    for name, server in servers:
        launcher.wait()


def _get_workers(worker_type_config_opt):
    # Get the value from config, if the config value is None (not set), return
    # the number of cpus with a minimum of 2.
    worker_count = CONF.eventlet_server.get(worker_type_config_opt)
    if not worker_count:
        worker_count = max(2, processutils.get_worker_count())
    return worker_count


def configure_threading():
    monkeypatch_thread = not CONF.standard_threads
    pydev_debug_url = utils.setup_remote_pydev_debug()
    if pydev_debug_url:
        # in order to work around errors caused by monkey patching we have to
        # set the thread to False.  An explanation is here:
        # http://lists.openstack.org/pipermail/openstack-dev/2012-August/
        # 000794.html
        monkeypatch_thread = False
    environment.use_eventlet(monkeypatch_thread)


def run(possible_topdir):
    dev_conf = os.path.join(possible_topdir,
                            'etc',
                            'keystone.conf')
    config_files = None
    if os.path.exists(dev_conf):
        config_files = [dev_conf]

    common.configure(
        version=pbr.version.VersionInfo('keystone').version_string(),
        config_files=config_files,
        pre_setup_logging_fn=configure_threading)

    paste_config = config.find_paste_config()

    def create_servers():
        admin_worker_count = _get_workers('admin_workers')
        public_worker_count = _get_workers('public_workers')

        servers = []
        servers.append(create_server(paste_config,
                                     'admin',
                                     CONF.eventlet_server.admin_bind_host,
                                     CONF.eventlet_server.admin_port,
                                     admin_worker_count))
        servers.append(create_server(paste_config,
                                     'main',
                                     CONF.eventlet_server.public_bind_host,
                                     CONF.eventlet_server.public_port,
                                     public_worker_count))
        return servers

    _unused, servers = common.setup_backends(
        startup_application_fn=create_servers)
    serve(*servers)
