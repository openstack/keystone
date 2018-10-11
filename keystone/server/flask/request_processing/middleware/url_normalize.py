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

# Flask Native URL Normalizing Middleware


class URLNormalizingMiddleware(object):
    """Middleware filter to handle URL normalization."""

    # NOTE(morgan): This must be a middleware as changing 'PATH_INFO' after
    # the request hits the flask app will not impact routing.

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        """Normalize URLs."""
        # TODO(morgan): evaluate collapsing multiple slashes in this middleware
        # e.g. '/v3//auth/tokens -> /v3/auth/tokens

        # Removes a trailing slashes from the given path, if any.
        if len(environ['PATH_INFO']) > 1 and environ['PATH_INFO'][-1] == '/':
            environ['PATH_INFO'] = environ['PATH_INFO'].rstrip('/')

        # Rewrites path to root if no path is given
        if not environ['PATH_INFO']:
            environ['PATH_INFO'] = '/'

        return self.app(environ, start_response)
