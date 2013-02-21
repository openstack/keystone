# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import routes

from keystone import auth
from keystone import catalog
from keystone.common import logging
from keystone.common import wsgi
from keystone.contrib import ec2
from keystone import identity
from keystone import policy
from keystone import routers
from keystone import token


LOG = logging.getLogger(__name__)

DRIVERS = dict(
    catalog_api=catalog.Manager(),
    ec2_api=ec2.Manager(),
    identity_api=identity.Manager(),
    policy_api=policy.Manager(),
    token_api=token.Manager())


@logging.fail_gracefully
def public_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Public(),
                                 token.routers.Router(),
                                 routers.Version('public'),
                                 routers.Extension(False)])


@logging.fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Admin(),
                                    token.routers.Router(),
                                    routers.Version('admin'),
                                    routers.Extension()])


@logging.fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('public')])


@logging.fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('admin')])


@logging.fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    mapper = routes.Mapper()
    v3routers = []
    for module in [auth, catalog, identity, policy]:
        module.routers.append_v3_routers(mapper, v3routers)
    # TODO(ayoung): put token routes here
    return wsgi.ComposingRouter(mapper, v3routers)
