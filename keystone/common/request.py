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

import logging

import webob
from webob.descriptors import environ_getter

from keystone.common import authorization
from keystone.common import context
import keystone.conf
from keystone import exception
from keystone.i18n import _, _LW


# Environment variable used to pass the request context
CONTEXT_ENV = 'openstack.context'

CONF = keystone.conf.CONF
LOG = logging.getLogger(__name__)


class Request(webob.Request):

    _context_dict = None

    def _get_context_dict(self):
        # allow middleware up the stack to provide context, params and headers.
        context = self.environ.get(CONTEXT_ENV, {})

        # NOTE(jamielennox): The webob package throws UnicodeError when a
        # param cannot be decoded. If we make webob iterate them now we can
        # catch this and throw an error early rather than on access.
        try:
            self.params.items()
        except UnicodeDecodeError:
            msg = _('Query string is not UTF-8 encoded')
            raise exception.ValidationError(msg)

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

        context.setdefault('is_admin', False)
        return context

    @property
    def context_dict(self):
        if not self._context_dict:
            self._context_dict = self._get_context_dict()

        return self._context_dict

    @property
    def auth_context(self):
        return self.environ.get(authorization.AUTH_CONTEXT_ENV, {})

    def assert_authenticated(self):
        """Ensure that the current request has been authenticated."""
        if not self.context:
            LOG.warning(_LW('An authenticated call was made and there is '
                            'no request.context. This means the '
                            'auth_context middleware is not in place. You '
                            'must have this middleware in your pipeline '
                            'to perform authenticated calls'))
            raise exception.Unauthorized()

        if not self.context.authenticated:
            # auth_context didn't decode anything we can use
            raise exception.Unauthorized()

    auth_type = environ_getter('AUTH_TYPE', None)
    remote_domain = environ_getter('REMOTE_DOMAIN', None)
    context = environ_getter(context.REQUEST_CONTEXT_ENV, None)
