# Copyright 2022 OpenStack Foundation
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

import flask
from keystone.server import flask as ks_flask


def build_response(error):
    response = flask.make_response((
        {
            'error': error.error_title,
            'error_description': error.message_format
        },
        f"{error.code} {error.title}"))

    if error.code == 401:
        response.headers['WWW-Authenticate'] = \
            'Keystone uri="%s"' % ks_flask.base_url()
    return response
