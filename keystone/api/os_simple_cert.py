#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This file handles all flask-restful resources for /v3/OS-SIMPLE-CERT

import flask
import flask_restful
import functools
from six.moves import http_client

from keystone.common import json_home
import keystone.conf
from keystone import exception
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF


_build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-SIMPLE-CERT', extension_version='1.0')


def _get_certificate(name):
    try:
        with open(name, 'r') as f:
            body = f.read()
    except IOError:
        raise exception.CertificateFilesUnavailable()
    resp = flask.make_response(body, http_client.OK)
    resp.headers['Content-Type'] = 'application/x-pem-file'
    return resp


class SimpleCertCAResource(flask_restful.Resource):
    @ks_flask.unenforced_api
    def get(self):
        return _get_certificate(CONF.signing.ca_certs)


class SimpleCertListResource(flask_restful.Resource):
    @ks_flask.unenforced_api
    def get(self):
        return _get_certificate(CONF.signing.certfile)


class SimpleCertAPI(ks_flask.APIBase):
    _name = 'OS-SIMPLE-CERT'
    _import_name = __name__
    resources = []
    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=SimpleCertCAResource,
            url='/OS-SIMPLE-CERT/ca',
            resource_kwargs={},
            rel='ca_certificate',
            resource_relation_func=_build_resource_relation),
        ks_flask.construct_resource_map(
            resource=SimpleCertListResource,
            url='/OS-SIMPLE-CERT/certificates',
            resource_kwargs={},
            rel='certificates',
            resource_relation_func=_build_resource_relation),
    ]


APIs = (SimpleCertAPI,)
