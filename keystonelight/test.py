import os
import unittest

from paste import deploy

from keystonelight import wsgi


ROOTDIR = os.path.dirname(os.path.dirname(__file__))
VENDOR = os.path.join(ROOTDIR, 'vendor')
TESTSDIR = os.path.join(ROOTDIR, 'tests')


class TestClient(object):
  def __init__(self, app=None, token=None):
    self.app = app
    self.token = token

  def request(self, method, path, headers=None, body=None):
    if headers is None:
      headers = {}

    if self.token:
      headers.setdefault('X-Auth-Token', self.token)

    req = wsgi.Request.blank(path)
    req.method = method
    for k, v in headers.iteritems():
      req.headers[k] = v
    if body:
      req.body = body
    return req.get_response(self.app)

  def get(self, path, headers=None):
    return self.request('GET', path=path, headers=headers)

  def post(self, path, headers=None, body=None):
    return self.request('POST', path=path, headers=headers, body=body)

  def put(self, path, headers=None, body=None):
    return self.request('PUT', path=path, headers=headers, body=body)


class TestCase(unittest.TestCase):
  def loadapp(self, config):
    if not config.startswith('config:'):
      config = 'config:%s.conf' % os.path.join(TESTSDIR, config)
    return deploy.loadapp(config)

  def appconfig(self, config):
    if not config.startswith('config:'):
      config = 'config:%s.conf' % os.path.join(TESTSDIR, config)
    return deploy.appconfig(config)

  def client(self, app, *args, **kw):
    return TestClient(app, *args, **kw)

  def assertListEquals(self, expected, actual):
    copy = expected[:]
    #print expected, actual
    self.assertEquals(len(expected), len(actual))
    while copy:
      item = copy.pop()
      matched = False
      for x in actual:
        #print 'COMPARE', item, x,
        try:
          self.assertDeepEquals(item, x)
          matched = True
          #print 'MATCHED'
          break
        except AssertionError as e:
          #print e
          pass
      if not matched:
        raise AssertionError('Expected: %s\n Got: %s' % (expected, actual))

  def assertDictEquals(self, expected, actual):
    for k in expected:
      self.assertTrue(k in actual,
                      "Expected key %s not in %s." % (k, actual))
      self.assertDeepEquals(expected[k], actual[k])

    for k in actual:
      self.assertTrue(k in expected,
                      "Unexpected key %s in %s." % (k, actual))

  def assertDeepEquals(self, expected, actual):
    try:
      if type(expected) is type([]) or type(expected) is type(tuple()):
        # assert items equal, ignore order
        self.assertListEquals(expected, actual)
      elif type(expected) is type({}):
        self.assertDictEquals(expected, actual)
      else:
        self.assertEquals(expected, actual)
    except AssertionError as e:
      raise
      raise AssertionError('Expected: %s\n Got: %s' % (expected, actual))


