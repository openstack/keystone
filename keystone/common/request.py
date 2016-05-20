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

from oslo_config import cfg
import webob

from keystone import exception
from keystone.i18n import _


# Environment variable used to pass the request context
CONTEXT_ENV = 'openstack.context'

CONF = cfg.CONF


class Request(webob.Request):

    _context_dict = None

    def _get_context_dict(self):
        # allow middleware up the stack to provide context, params and headers.
        context = self.environ.get(CONTEXT_ENV, {})

        try:
            context['query_string'] = dict(self.params.items())
        except UnicodeDecodeError:
            # The webob package throws UnicodeError when a request cannot be
            # decoded. Raise ValidationError instead to avoid an UnknownError.
            msg = _('Query string is not UTF-8 encoded')
            raise exception.ValidationError(msg)

        context['headers'] = dict(self.headers.items())
        context['path'] = self.environ['PATH_INFO']
        scheme = self.environ.get(CONF.secure_proxy_ssl_header)
        if scheme:
            # NOTE(andrey-mp): "wsgi.url_scheme" contains the protocol used
            # before the proxy removed it ('https' usually). So if
            # the webob.Request instance is modified in order to use this
            # scheme instead of the one defined by API, the call to
            # webob.Request.relative_url() will return a URL with the correct
            # scheme.
            self.environ['wsgi.url_scheme'] = scheme
        context['host_url'] = self.host_url
        # authentication and authorization attributes are set as environment
        # values by the container and processed by the pipeline. The complete
        # set is not yet known.
        context['environment'] = self.environ
        context['accept_header'] = self.accept

        context.setdefault('is_admin', False)
        return context

    @property
    def context_dict(self):
        if not self._context_dict:
            self._context_dict = self._get_context_dict()

        return self._context_dict
