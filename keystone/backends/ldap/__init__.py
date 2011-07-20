import ldap

import keystone.backends.api as top_api
import keystone.backends.models as top_models
from keystone import utils

from . import api
from . import models


def configure_backend(options):
    api_obj = api.API(options)
    for name in api_obj.apis:
        top_api.set_value(name, getattr(api_obj, name))
    for model_name in models.__all__:
        top_models.set_value(model_name, getattr(models, model_name))
