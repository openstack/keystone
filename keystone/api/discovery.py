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

import flask
from flask import request
import http.client
from oslo_serialization import jsonutils

from keystone.common import json_home
import keystone.conf
from keystone.server import flask as ks_flask


CONF = keystone.conf.CONF
MEDIA_TYPE_JSON = 'application/vnd.openstack.identity-%s+json'
_DISCOVERY_BLUEPRINT = flask.Blueprint('Discovery', __name__)


def _get_versions_list(identity_url):
    versions = {}
    versions['v3'] = {
        'id': 'v3.14',
        'status': 'stable',
        'updated': '2020-04-07T00:00:00Z',
        'links': [{
            'rel': 'self',
            'href': identity_url,
        }],
        'media-types': [{
            'base': 'application/json',
            'type': MEDIA_TYPE_JSON % 'v3'
        }]
    }
    return versions


class MimeTypes(object):
    JSON = 'application/json'
    JSON_HOME = 'application/json-home'


def v3_mime_type_best_match():
    if not request.accept_mimetypes:
        return MimeTypes.JSON

    return request.accept_mimetypes.best_match(
        [MimeTypes.JSON, MimeTypes.JSON_HOME])


@_DISCOVERY_BLUEPRINT.route('/')
def get_versions():
    if v3_mime_type_best_match() == MimeTypes.JSON_HOME:
        # RENDER JSON-Home form, we have a clever client who will
        # understand the JSON-Home document.
        v3_json_home = json_home.JsonHomeResources.resources()
        json_home.translate_urls(v3_json_home, '/v3')
        return flask.Response(response=jsonutils.dumps(v3_json_home),
                              mimetype=MimeTypes.JSON_HOME)
    else:
        identity_url = '%s/' % ks_flask.base_url()
        versions = _get_versions_list(identity_url)
        # Set the preferred version to the latest "stable" version.
        # TODO(morgan): If we ever have more API versions find the latest
        # stable version instead of just using the "base_url", for now we
        # simply have a single version so use it as the preferred location.
        preferred_location = identity_url

        response = flask.Response(
            response=jsonutils.dumps(
                {'versions': {
                    'values': list(versions.values())}}),
            mimetype=MimeTypes.JSON,
            status=http.client.MULTIPLE_CHOICES)
        response.headers['Location'] = preferred_location
        return response


@_DISCOVERY_BLUEPRINT.route('/v3')
def get_version_v3():
    if v3_mime_type_best_match() == MimeTypes.JSON_HOME:
        # RENDER JSON-Home form, we have a clever client who will
        # understand the JSON-Home document.
        content = json_home.JsonHomeResources.resources()
        return flask.Response(response=jsonutils.dumps(content),
                              mimetype=MimeTypes.JSON_HOME)
    else:
        identity_url = '%s/' % ks_flask.base_url()
        versions = _get_versions_list(identity_url)
        return flask.Response(
            response=jsonutils.dumps({'version': versions['v3']}),
            mimetype=MimeTypes.JSON)


class DiscoveryAPI(object):
    # NOTE(morgan): The Discovery Bits are so special they cannot conform to
    # Flask-RESTful-isms. We are using straight flask Blueprint(s) here so that
    # we have a lot more control over what the heck is going on. This is just
    # a stub object to ensure we can load discovery in the same manner we
    # handle the rest of keystone.api

    @staticmethod
    def instantiate_and_register_to_app(flask_app):
        # This is a lot more magical than the normal setup as the discovery
        # API does not lean on flask-restful. We're statically building a
        # single blueprint here.
        flask_app.register_blueprint(_DISCOVERY_BLUEPRINT)


APIs = (DiscoveryAPI,)
