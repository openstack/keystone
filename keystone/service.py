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

from oslo_log import versionutils
import six

from keystone.version import service


def deprecated_to_version(f):
    """Specialized deprecation wrapper for service module.

    This wraps the standard deprecation wrapper and fills in the method
    names automatically.

    """
    @six.wraps(f)
    def wrapper(*args, **kwargs):
        x = versionutils.deprecated(
            what='keystone.service.' + f.__name__ + '()',
            as_of=versionutils.deprecated.MITAKA,
            remove_in=+2,
            in_favor_of='keystone.version.service.' + f.__name__ + '()')
        return x(f)
    return wrapper()


@deprecated_to_version
def public_app_factory(global_conf, **local_conf):
    return service.public_app_factory(global_conf, **local_conf)


@deprecated_to_version
def admin_app_factory(global_conf, **local_conf):
    return service.admin_app_factory(global_conf, **local_conf)


@deprecated_to_version
def public_version_app_factory(global_conf, **local_conf):
    return service.public_version_app_factory(global_conf, **local_conf)


@deprecated_to_version
def admin_version_app_factory(global_conf, **local_conf):
    return service.admin_app_factory(global_conf, **local_conf)


@deprecated_to_version
def v3_app_factory(global_conf, **local_conf):
    return service.v3_app_factory(global_conf, **local_conf)
