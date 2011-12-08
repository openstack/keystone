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

# pylint: disable=W0603
import ast
import logging
from keystone import utils
from keystone.backends import models
from keystone.backends import api

DEFAULT_BACKENDS = 'keystone.backends.sqlalchemy'

#Configs applicable to all backends.
#Reference to Admin Role.
ADMIN_ROLE_ID = None
ADMIN_ROLE_NAME = None
SERVICE_ADMIN_ROLE_ID = None
SERVICE_ADMIN_ROLE_NAME = None
SHOULD_HASH_PASSWORD = None


def configure_backends(options):
    '''Load backends given in the 'backends' option.'''
    backend_names = options.get('backends', DEFAULT_BACKENDS)
    if backend_names:
        for backend in backend_names.split(','):
            backend_module = utils.import_module(backend)
            backend_module.configure_backend(options[backend])

    #Initialize common configs general to all backends.
    global ADMIN_ROLE_NAME
    ADMIN_ROLE_NAME = options["keystone-admin-role"]

    global SERVICE_ADMIN_ROLE_NAME
    SERVICE_ADMIN_ROLE_NAME = options["keystone-service-admin-role"]

    global SHOULD_HASH_PASSWORD
    if "hash-password" in options\
        and ast.literal_eval(options["hash-password"]) == True:
        SHOULD_HASH_PASSWORD = options["hash-password"]
