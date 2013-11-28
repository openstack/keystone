# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import webob.dec

from keystone.common import wsgi
from keystone import config
from keystone.openstack.common import log as logging
from keystone.openstack.common import timeutils


CONF = config.CONF
LOG = logging.getLogger('access')
APACHE_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S'
APACHE_LOG_FORMAT = (
    '%(remote_addr)s - %(remote_user)s [%(datetime)s] "%(method)s %(url)s '
    '%(http_version)s" %(status)s %(content_length)s')


class AccessLogMiddleware(wsgi.Middleware):
    """Writes an access log to INFO."""

    @webob.dec.wsgify
    def __call__(self, request):
        data = {
            'remote_addr': request.remote_addr,
            'remote_user': request.remote_user or '-',
            'method': request.method,
            'url': request.url,
            'http_version': request.http_version,
            'status': 500,
            'content_length': '-'}

        try:
            response = request.get_response(self.application)
            data['status'] = response.status_int
            data['content_length'] = len(response.body) or '-'
        finally:
            # must be calculated *after* the application has been called
            now = timeutils.utcnow()

            # timeutils may not return UTC, so we can't hardcode +0000
            data['datetime'] = '%s %s' % (now.strftime(APACHE_TIME_FORMAT),
                                          now.strftime('%z') or '+0000')

            LOG.info(APACHE_LOG_FORMAT, data)
        return response
