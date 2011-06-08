#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
# Not Yet PEP8 standardized


"""
RACKSPACE LEGACY AUTH - STUB

This WSGI component  
- collects, transforms and forwards identity information from the keystone authentication process
    into rackspace specific format.
"""
import os
import sys
import routes
import eventlet
import optparse
import httplib2
import json
import ast

from webob import Response
from paste.deploy import loadapp
from webob.exc import HTTPUnauthorized, HTTPInternalServerError

POSSIBLE_TOPDIR = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(POSSIBLE_TOPDIR, 'keystone', '__init__.py')):
    sys.path.insert(0, POSSIBLE_TOPDIR)

import keystone
import keystone.utils as utils
from keystone.common import wsgi
from keystone.common import config

class RackspaceLegacyAuthController(wsgi.Controller):
    """
        Auth Controller for v1.x -
        Controller for token related operations
    """

    def __init__(self, options):
        self.options = options
        self.request = None
         # where to find the auth service (we use this to validate tokens)
        self.auth_host = options.get('auth_host')
        self.auth_port = int(options.get('auth_port'))
        self.auth_protocol = options.get('auth_protocol', 'https')
        self.auth_location = "%s://%s:%s" % (self.auth_protocol,
                                             self.auth_host,
                                             self.auth_port)

    @utils.wrap_error
    def authenticate(self, req):
        header = httplib2.Http(".cache")
        self.request = req
    
        url = '%s/v2.0/tokens' % self.auth_location

        body = {"passwordCredentials": {"username": utils.get_auth_user(self.request),
                "password": utils.get_auth_key(self.request)}}

        resp, content = header.request(url, "POST", body=json.dumps(body),
            headers={"Content-Type": "application/json"})
    
        if int(resp['status']) != 200:
            response = Response()
            response.status = resp.status
            response.reason = resp.reason
            return response
            
        content = json.loads(content)
        
        headers = {}
        
        if "auth" in content:
            auth = content["auth"]
            
            if "token" in auth:
                headers["X-Auth-Token"] = auth["token"]["id"]
        
            if "serviceCatalog" in auth:
                services = auth["serviceCatalog"]
                service_mappings = ast.literal_eval(self.options["service-header-mappings"])
                for service in services:
                    service_name = service
                    service_urls = ''
                    for endpoint in services[service_name]:
                        if len(service_urls) > 0:
                            service_urls += ','
                        service_urls += endpoint["publicURL"]
                    if len(service_urls) > 0:
                        if service_mappings.get(service_name):
                            headers[service_mappings.get(service_name)] = service_urls
                        else:
                            #For Services that are not mapped user X- prefix followed by service name.
                            headers['X-' + service_name.upper()] = service_urls
        return utils.send_legacy_result(204, headers)

class RackspaceLegacyAuthenticator(wsgi.Router):
    """Rackspace Legacy Protocol that handles authenticating client calls made in Rackspace format."""

    def __init__(self, options):
        self.options = options
        mapper = routes.Mapper()
        # Legacy Token Operations
        legacy_auth_controller = RackspaceLegacyAuthController(options)
        mapper.connect("/v1.0", controller=legacy_auth_controller,
                       action="authenticate")
        mapper.connect("/v1.0/", controller=legacy_auth_controller,
                       action="authenticate")
        mapper.connect("/v1.1/tokens", controller=legacy_auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        mapper.connect("/v1.1/tokens/", controller=legacy_auth_controller,
                       action="authenticate",
                       conditions=dict(method=["POST"]))
        super(RackspaceLegacyAuthenticator, self).__init__(mapper)

def app_factory(global_conf, ** local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return RackspaceLegacyAuthenticator(conf)

if __name__ == "__main__":
    expected_options = {'verbose': False, 'debug': False,
                            'config_file': 'rackspace_legacy_auth.conf'}
    
    parser = optparse.OptionParser(version='%%prog %s' % keystone.version)
    # Parse arguments and load config
    (options, args) = config.parse_options(parser)
    # Start services
    try:
        conf, app = config.load_paste_app('rackspace_legacy_auth', expected_options, args)
        server = wsgi.Server()
        server.start(app, int(conf['bind_port']), conf['bind_host'])
        print "Rackspace Legacy Service API listening on %s:%s" % (conf['bind_host'],
                                              conf['bind_port'])
        server.wait()

    except RuntimeError, e:
        sys.exit("ERROR: %s" % e)

