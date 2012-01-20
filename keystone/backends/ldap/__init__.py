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

import ldap

import keystone.backends.api as top_api
import keystone.backends.models as top_models
from keystone import utils

from . import api
from . import models


def configure_backend(conf):
    api_obj = api.API(conf)
    for name in api_obj.apis:
        top_api.set_value(name, getattr(api_obj, name))
    for model_name in models.__all__:
        top_models.set_value(model_name, getattr(models, model_name))
