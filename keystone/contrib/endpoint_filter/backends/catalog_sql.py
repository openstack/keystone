# Copyright 2013 OpenStack Foundation
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

from keystone.catalog.backends import sql
import keystone.conf


CONF = keystone.conf.CONF


@versionutils.deprecated(
    what=('keystone.contrib.endpoint_filter.'
          'backends.catalog_sql.EndPointFilterCatalog'),
    as_of=versionutils.deprecated.OCATA,
    remove_in=+1,
    in_favor_of='keystone.catalog.backends.sql.Catalog')
class EndpointFilterCatalog(sql.Catalog):
    def get_v3_catalog(self, user_id, project_id):
        return super(EndpointFilterCatalog, self).get_v3_catalog(
            user_id, project_id)
