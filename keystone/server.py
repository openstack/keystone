# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Service that stores identities and issues and manages tokens

HEADERS
-------

* HTTP\_ is a standard http header
* HTTP_X is an extended http header

Coming in from initial call
^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTH_TOKEN
    the client token being passed in

HTTP_X_STORAGE_TOKEN
    the client token being passed in (legacy Rackspace use) to support
    cloud files

Used for communication between components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

www-authenticate
    only used if this component is being used remotely

HTTP_AUTHORIZATION
    basic auth password used to validate the connection

What we add to the request for use by the OpenStack SERVICE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HTTP_X_AUTHORIZATION
    the client identity being passed in

"""

# pylint: disable=W0613

import logging

from keystone import config
from keystone.common import config as common_config
from keystone.common import wsgi
from keystone.routers.service import ServiceApi
from keystone.routers.admin import AdminApi

CONF = config.CONF

logger = logging.getLogger(__name__)  # pylint: disable=C0103


def service_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    return ServiceApi()


def admin_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    return AdminApi()


# pylint: disable=R0902
class Server():
    """Used to start and stop Keystone servers

    This class is called from shell and command-line scripts and is the
    entry-point for starting and stopping Keystone servers.

    The initializer can take option and argument overrides, but otherwise will
    parse arguments and configuration files itself to determine how to start
    the server.
    """

    def __init__(self, name='admin', config_name=None, args=None):
        """Initizalizer which takes the following paramaters:

        :param name: A cosmetic name for the server (ex. Admin API)
        :param config: the paste config name to look for when starting the
            server
        :param args: override for sys.argv (otherwise sys.argv is used)
        """
        logger.debug("Init server '%s' with config=%s" % (name, config_name))

        self.name = name
        self.config = config_name or self.name
        self.args = args
        self.key = None
        self.server = None
        self.port = None
        self.host = None
        self.protocol = None
        self.options = CONF.to_dict()

    def start(self, host=None, port=None, wait=True):
        """Starts the Keystone server

        :param host: the IP address to listen on
        :param port: the TCP/IP port to listen on
        :param wait: whether to wait (block) for the server to terminate or
            return to the caller without waiting
        """
        logger.debug("Starting API server")
        conf, app = common_config.load_paste_app(self.config, self.options,
                self.args)

        debug = CONF.debug in [True, "True", "1"]
        verbose = CONF.verbose in [True, "True", "1"]

        if debug or verbose:
            config_file = common_config.find_config_file(self.options,
                    self.args)
            logger.info("Starting '%s' with config: %s" %
                                   (self.config, config_file))

        if port is None:
            if self.config == 'admin':
                # Legacy
                port = int(CONF.admin_port or 35357)
            else:
                port = int(CONF.service_port or CONF.bind_port or 5000)
        if host is None:
            host = CONF.bind_host or CONF.service_host or "0.0.0.0"

        self.key = "%s-%s:%s" % (self.name, host, port)

        # Safely get SSL options
        service_ssl = CONF.service_ssl in [True, "True", "1"]

        # Load the server
        if service_ssl:
            cert_required = conf.get('cert_required', False)
            cert_required = cert_required in [True, "True", "1"]
            certfile = conf.get('certfile')
            keyfile = conf.get('keyfile')
            ca_certs = conf.get('ca_certs')

            self.server = wsgi.SslServer()
            self.server.start(app, port, host,
                         certfile=certfile, keyfile=keyfile,
                         ca_certs=ca_certs,
                         cert_required=cert_required,
                         key=self.key)
            self.protocol = 'https'
        else:
            self.server = wsgi.Server()
            self.server.start(app, port, host,
                              key="%s-%s:%s" % (self.config, host, port))
            self.protocol = 'http'

        self.port = port
        self.host = host

        logger.info("%s listening on %s://%s:%s" % (
            self.name, ['http', 'https'][service_ssl], host, port))

        # Wait until done
        if wait:
            self.server.wait()

    def stop(self):
        """Stops the Keystone server

        This should be called always to release the network socket
        """
        if self.server is not None:
            if self.key in self.server.threads:
                logger.debug("Killing %s" % self.key)
                self.server.threads[self.key].kill()
            self.server = None
