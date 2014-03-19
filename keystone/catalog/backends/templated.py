# Copyright 2012 OpenStack Foundationc
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

import os.path

import six

from keystone.catalog.backends import kvs
from keystone.catalog import core
from keystone import config
from keystone import exception
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log
from keystone.openstack.common import versionutils


LOG = log.getLogger(__name__)

CONF = config.CONF


def parse_templates(template_lines):
    o = {}
    for line in template_lines:
        if ' = ' not in line:
            continue

        k, v = line.strip().split(' = ')
        if not k.startswith('catalog.'):
            continue

        parts = k.split('.')

        region = parts[1]
        # NOTE(termie): object-store insists on having a dash
        service = parts[2].replace('_', '-')
        key = parts[3]

        region_ref = o.get(region, {})
        service_ref = region_ref.get(service, {})
        service_ref[key] = v

        region_ref[service] = service_ref
        o[region] = region_ref

    return o


class Catalog(kvs.Catalog):
    """A backend that generates endpoints for the Catalog based on templates.

    It is usually configured via config entries that look like:

      catalog.$REGION.$SERVICE.$key = $value

    and is stored in a similar looking hierarchy. Where a value can contain
    values to be interpolated by standard python string interpolation that look
    like (the % is replaced by a $ due to paste attempting to interpolate on
    its own:

      http://localhost:$(public_port)s/

    When expanding the template it will pass in a dict made up of the conf
    instance plus a few additional key-values, notably tenant_id and user_id.

    It does not care what the keys and values are but it is worth noting that
    keystone_compat will expect certain keys to be there so that it can munge
    them into the output format keystone expects. These keys are:

      name - the name of the service, most likely repeated for all services of
             the same type, across regions.

      adminURL - the url of the admin endpoint

      publicURL - the url of the public endpoint

      internalURL - the url of the internal endpoint

    """

    def __init__(self, templates=None):
        super(Catalog, self).__init__()
        if templates:
            self.templates = templates
        else:
            template_file = CONF.catalog.template_file
            if not os.path.exists(template_file):
                template_file = CONF.find_file(template_file)
            self._load_templates(template_file)

    def _load_templates(self, template_file):
        try:
            self.templates = parse_templates(open(template_file))
        except IOError:
            LOG.critical(_('Unable to open template file %s'), template_file)
            raise

    def get_catalog(self, user_id, tenant_id, metadata=None):
        d = dict(six.iteritems(CONF))
        d.update({'tenant_id': tenant_id,
                  'user_id': user_id})

        o = {}
        for region, region_ref in six.iteritems(self.templates):
            o[region] = {}
            for service, service_ref in six.iteritems(region_ref):
                service_data = {}
                try:
                    for k, v in six.iteritems(service_ref):
                        service_data[k] = core.format_url(v, d)
                except exception.MalformedEndpoint:
                    continue  # this failure is already logged in format_url()
                o[region][service] = service_data

        return o


@versionutils.deprecated(
    versionutils.deprecated.ICEHOUSE,
    in_favor_of='keystone.catalog.backends.templated.Catalog',
    remove_in=+2)
class TemplatedCatalog(Catalog):
    pass
