# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools
import sys

from oslo_config import cfg
from oslo_log import log
from paste import deploy
import routes

from keystone import assignment
from keystone import auth
from keystone import catalog
from keystone.common import wsgi
from keystone import controllers
from keystone import credential
from keystone import endpoint_policy
from keystone import identity
from keystone import policy
from keystone import resource
from keystone import routers
from keystone import token
from keystone import trust


CONF = cfg.CONF
LOG = log.getLogger(__name__)


def loadapp(conf, name):
    # NOTE(blk-u): Save the application being loaded in the controllers module.
    # This is similar to how public_app_factory() and v3_app_factory()
    # register the version with the controllers module.
    controllers.latest_app = deploy.loadapp(conf, name=name)
    return controllers.latest_app


def fail_gracefully(f):
    """Logs exceptions and aborts."""
    @functools.wraps(f)
    def wrapper(*args, **kw):
        try:
            return f(*args, **kw)
        except Exception as e:
            LOG.debug(e, exc_info=True)

            # exception message is printed to all logs
            LOG.critical(e)
            sys.exit(1)

    return wrapper


@fail_gracefully
def public_app_factory(global_conf, **local_conf):
    controllers.register_version('v2.0')
    return wsgi.ComposingRouter(routes.Mapper(),
                                [assignment.routers.Public(),
                                 token.routers.Router(),
                                 routers.VersionV2('public'),
                                 routers.Extension(False)])


@fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    controllers.register_version('v2.0')
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Admin(),
                                 assignment.routers.Admin(),
                                    token.routers.Router(),
                                    resource.routers.Admin(),
                                    routers.VersionV2('admin'),
                                    routers.Extension()])


@fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('public')])


@fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('admin')])


@fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    controllers.register_version('v3')
    mapper = routes.Mapper()
    sub_routers = []
    _routers = []

    # NOTE(dstanek): Routers should be ordered by their frequency of use in
    # a live system. This is due to the routes implementation. The most
    # frequently used routers should appear first.
    router_modules = [auth,
                      assignment,
                      catalog,
                      credential,
                      identity,
                      policy,
                      resource]

    if CONF.trust.enabled:
        router_modules.append(trust)

    if CONF.endpoint_policy.enabled:
        router_modules.append(endpoint_policy)

    for module in router_modules:
        routers_instance = module.routers.Routers()
        _routers.append(routers_instance)
        routers_instance.append_v3_routers(mapper, sub_routers)

    # Add in the v3 version api
    sub_routers.append(routers.VersionV3('public', _routers))
    return wsgi.ComposingRouter(mapper, sub_routers)
