# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
import ast
import logging
import keystone.utils as utils
from keystone.backends import models as models
from keystone.backends import api as api

DEFAULT_BACKENDS = 'keystone.backends.sqlalchemy'

#Configs applicable to all backends.
#Reference to Admin Role.
KEYSTONEADMINROLE = None
KEYSTONESERVICEADMINROLE = None


def configure_backends(options):
    '''Load backends given in the 'backends' option.'''
    backend_names = options.get('backends', DEFAULT_BACKENDS)
    for backend in backend_names.split(','):
        backend_module = utils.import_module(backend)
        backend_module.configure_backend(options[backend])
        #Initialize common configs general to all backends.
        global KEYSTONEADMINROLE
        KEYSTONEADMINROLE = options["keystone-admin-role"]
        global KEYSTONESERVICEADMINROLE
        KEYSTONESERVICEADMINROLE = options["keystone-service-admin-role"]
