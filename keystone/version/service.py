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

from oslo_log import log
from paste import deploy
import routes

from keystone.assignment import routers as assignment_routers
from keystone.auth import routers as auth_routers
from keystone.catalog import routers as catalog_routers
from keystone.common import wsgi
import keystone.conf
from keystone.credential import routers as credential_routers
from keystone.endpoint_policy import routers as endpoint_policy_routers
from keystone.federation import routers as federation_routers
from keystone.i18n import _LW
from keystone.identity import routers as identity_routers
from keystone.oauth1 import routers as oauth1_routers
from keystone.policy import routers as policy_routers
from keystone.resource import routers as resource_routers
from keystone.revoke import routers as revoke_routers
from keystone.token import _simple_cert as simple_cert_ext
from keystone.token import routers as token_routers
from keystone.trust import routers as trust_routers
from keystone.v2_crud import admin_crud
from keystone.v2_crud import user_crud
from keystone.version import controllers
from keystone.version import routers


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


def loadapp(conf, name):
    # NOTE(blk-u): Save the application being loaded in the controllers module.
    # This is similar to how public_app_factory() and v3_app_factory()
    # register the version with the controllers module.
    controllers.latest_app = deploy.loadapp(conf, name=name)
    return controllers.latest_app


def fail_gracefully(f):
    """Log exceptions and aborts."""
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


def warn_local_conf(f):
    @functools.wraps(f)
    def wrapper(*args, **local_conf):
        if local_conf:
            LOG.warning(_LW('\'local conf\' from PasteDeploy INI is being '
                            'ignored.'))
        return f(*args, **local_conf)
    return wrapper


@fail_gracefully
@warn_local_conf
def public_app_factory(global_conf, **local_conf):
    controllers.register_version('v2.0')
    return wsgi.ComposingRouter(routes.Mapper(),
                                [assignment_routers.Public(),
                                 token_routers.Router(),
                                 user_crud.Router(),
                                 routers.VersionV2('public'),
                                 routers.Extension(False)])


@fail_gracefully
@warn_local_conf
def admin_app_factory(global_conf, **local_conf):
    controllers.register_version('v2.0')
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity_routers.Admin(),
                                 assignment_routers.Admin(),
                                 token_routers.Router(),
                                 resource_routers.Admin(),
                                 admin_crud.Router(),
                                 routers.VersionV2('admin'),
                                 routers.Extension()])


@fail_gracefully
@warn_local_conf
def public_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('public')])


@fail_gracefully
@warn_local_conf
def admin_version_app_factory(global_conf, **local_conf):
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('admin')])


@fail_gracefully
@warn_local_conf
def v3_app_factory(global_conf, **local_conf):
    controllers.register_version('v3')
    mapper = routes.Mapper()
    sub_routers = []
    _routers = []

    # NOTE(dstanek): Routers should be ordered by their frequency of use in
    # a live system. This is due to the routes implementation. The most
    # frequently used routers should appear first.
    all_api_routers = [auth_routers,
                       assignment_routers,
                       catalog_routers,
                       credential_routers,
                       identity_routers,
                       policy_routers,
                       resource_routers,
                       revoke_routers,
                       federation_routers,
                       oauth1_routers,
                       endpoint_policy_routers,
                       # TODO(morganfainberg): Remove the simple_cert router
                       # when PKI and PKIZ tokens are removed.
                       simple_cert_ext]

    if CONF.trust.enabled:
        all_api_routers.append(trust_routers)

    for api_routers in all_api_routers:
        routers_instance = api_routers.Routers()
        _routers.append(routers_instance)
        routers_instance.append_v3_routers(mapper, sub_routers)

    # Add in the v3 version api
    sub_routers.append(routers.VersionV3('public', _routers))
    return wsgi.ComposingRouter(mapper, sub_routers)
