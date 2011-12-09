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
import sys
import optparse

from keystone import version
from keystone.routers.service import ServiceApi
from keystone.routers.admin import AdminApi
from keystone.common import config, wsgi


def service_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ServiceApi(conf)


def admin_app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating OpenStack API server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return AdminApi(conf)


class Server():
    """Used to start and stop Keystone servers

    This class is called from shell and command-line scripts and is the
    entry-point for starting and stopping Keystone servers.

    The initializer can take option and argument overrides, but otherwise will
    parse arguments and configuration files itself to determine how to start
    the server.
    """

    def __init__(self, name='admin', config_name=None,
                 options=None, args=None):
        """Initizalizer which takes the following paramaters:

        :param name: A cosmetic name for the server (ex. Admin API)
        :param config: the paste config name to look for when starting the
            server
        :param options: a mapping of option key/str(value) pairs passed to
            config.load_paste_app
        :param args: override for sys.argv (otherwise sys.argv is used)
        """
        self.options = options
        if args:
            self.args = args
        else:
            self.args = sys.argv

        if options is None or args is None:
            # Initialize a parser for our configuration paramaters
            parser = optparse.OptionParser(version='%%prog %s' %
                                           version.version())
            common_group = config.add_common_options(parser)
            config.add_log_options(parser)

            # Parse arguments and load config
            (poptions, pargs) = config.parse_options(parser)

        if options is None:
            self.options = poptions
        else:
            self.options = options

        if args is None:
            self.args = pargs
        else:
            self.args = args

        self.name = name
        self.config = config_name or self.name

    def start(self, host=None, port=None, wait=True):
        """Starts the Keystone server

        :param host: the IP address to listen on
        :param port: the TCP/IP port to listen on
        :param wait: whether to wait (block) for the server to terminate or
            return to the caller without waiting
        """
        # Load Service API server
        conf, app = config.load_paste_app(
            self.config, self.options, self.args)

        debug = self.options.get('debug') or conf.get('debug', False)
        debug = debug in [True, "True", "1"]
        verbose = self.options.get('verbose') or conf.get('verbose', False)
        verbose = verbose in [True, "True", "1"]

        if debug or verbose:
            config_file = config.find_config_file(self.options, self.args)
            print "Starting '%s' with config: %s" % (self.config, config_file)

        if port is None:
            if self.config == 'admin':
                # Legacy
                port = int(self.options.get('bind_port') or
                           conf.get('admin_port', 35357))
            else:
                port = int(self.options.get('bind_port') or
                           conf.get('service_port', 5000))
        if host is None:
            host = self.options.get('bind_host',
                                    conf.get('service_host', '0.0.0.0'))

        self.key = "%s-%s:%s" % (self.name, host, port)

        # Safely get SSL options
        service_ssl = conf.get('service_ssl', False)
        service_ssl = service_ssl in [True, "True", "1"]

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
        else:
            self.server = wsgi.Server()
            self.server.start(app, port, host,
                              key="%s-%s:%s" % (self.config, host, port))

        print "%s listening on %s://%s:%s" % (
            self.name, ['http', 'https'][service_ssl], host, port)

        # Wait until done
        if wait:
            self.server.wait()

    def stop(self):
        """Stops the Keystone server

        This should be called always to release the network socket
        """
        if self.server is not None:
            if self.key in self.server.threads:
                self.server.threads[self.key].kill()
            self.server = None
