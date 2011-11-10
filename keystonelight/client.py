
"""Client library for KeystoneLight API."""

import json

import httplib2
import webob

from keystonelight import wsgi


class Client(object):
  def __init__(self, token=None):
    self.token = token

  def request(self, method, path, headers, body):
    raise NotImplemented

  def get(self, path, headers=None):
    return self.request('GET', path=path, headers=headers)

  def post(self, path, headers=None, body=None):
    return self.request('POST', path=path, headers=headers, body=body)

  def put(self, path, headers=None, body=None):
    return self.request('PUT', path=path, headers=headers, body=body)

  def _build_headers(self, headers=None):
    if headers is None:
      headers = {}

    if self.token:
      headers.setdefault('X-Auth-Token', self.token)

    return headers


class HttpClient(Client):
  def __init__(self, endpoint=None, token=None):
    self.endpoint = endpoint
    super(HttpClient, self).__init__(token=token)

  def request(self, method, path, headers=None, body=None):
    if type(body) is type({}):
      body = json.dumps(body)
    headers = self._build_headers(headers)
    h = httplib.Http()
    resp, content = h.request(path, method=method, headers=headers, body=body)
    return webob.Response(content, status=resp.status, headerlist=resp.headers)


class TestClient(Client):
  def __init__(self, app=None, token=None):
    self.app = app
    super(TestClient, self).__init__(token=token)

  def request(self, method, path, headers=None, body=None):
    if type(body) is type({}):
      body = json.dumps(body)
    headers = self._build_headers(headers)
    req = wsgi.Request.blank(path)
    req.method = method
    for k, v in headers.iteritems():
      req.headers[k] = v
    if body:
      req.body = body
    return req.get_response(self.app)
