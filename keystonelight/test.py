import ConfigParser
import logging
import os
import unittest
import subprocess
import sys

from paste import deploy

from keystonelight import logging
from keystonelight import models
from keystonelight import utils
from keystonelight import wsgi


ROOTDIR = os.path.dirname(os.path.dirname(__file__))
VENDOR = os.path.join(ROOTDIR, 'vendor')
TESTSDIR = os.path.join(ROOTDIR, 'tests')


cd = os.chdir


def checkout_vendor(repo, rev):
  name = repo.split('/')[-1]
  if name.endswith('.git'):
    name = name[:-4]

  revdir = os.path.join(VENDOR, '%s-%s' % (name, rev.replace('/', '_')))
  try:
    if not os.path.exists(revdir):
      utils.git('clone', repo, revdir)

    cd(revdir)
    utils.git('pull')
    utils.git('checkout', '-q', rev)
  except subprocess.CalledProcessError as e:
    logging.warning('Failed to checkout %s', repo)
    pass
  return revdir


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
  def __init__(self, *args, **kw):
    super(TestCase, self).__init__(*args, **kw)
    self._paths = []
    self._memo = {}

  def setUp(self):
    super(TestCase, self).setUp()

  def tearDown(self):
    for path in self._paths:
      if path in sys.path:
        sys.path.remove(path)
    super(TestCase, self).tearDown()

  def load_fixtures(self, fixtures):
    """Really quite basic and naive fixture loading based on a python module.

    Expects that the various APIs into the various services are already
    defined on `self`.

    """
    # TODO(termie): doing something from json, probably based on Django's
    #               loaddata will be much preferred.
    for tenant in fixtures.TENANTS:
      rv = self.identity_api.create_tenant(
          tenant['id'], models.Tenant(**tenant))
      setattr(self, 'tenant_%s' % tenant['id'], rv)

    for user in fixtures.USERS:
      rv = self.identity_api.create_user(user['id'], models.User(**user))
      setattr(self, 'user_%s' % user['id'], rv)

    for role in fixtures.ROLES:
      rv = self.identity_api.create_role(role['id'], models.Role(**role))
      setattr(self, 'role_%s' % role['id'], rv)

    for extras in fixtures.EXTRAS:
      extras_ref = extras.copy()
      del extras_ref['user']
      del extras_ref['tenant']
      rv = self.identity_api.create_extras(
          extras['user'], extras['tenant'], models.Extras(**extras_ref))
      setattr(self, 'extras_%s%s' % (extras['user'], extras['tenant']), rv)

  def loadapp(self, config):
    if not config.startswith('config:'):
      config = 'config:%s.conf' % os.path.join(TESTSDIR, config)
    return deploy.loadapp(config)

  def appconfig(self, config):
    if not config.startswith('config:'):
      config = 'config:%s.conf' % os.path.join(TESTSDIR, config)
    return deploy.appconfig(config)

  def serveapp(self, config):
    app = self.loadapp(config)
    server = wsgi.Server()
    server.start(app, 0, key='socket')

    # Service catalog tests need to know the port we ran on.
    port = server.socket_info['socket'][1]
    self._update_server_options(server, 'public_port', port)
    return server

  def _update_server_options(self, server, key, value):
    """Hack to allow us to make changes to the options used by backends.

    A possible better solution would be to have a global config registry.

    """
    last = server

    applications = []

    while (hasattr(last, 'applications')
           or hasattr(last, 'application')
           or hasattr(last, 'options')):

      logging.debug('UPDATE %s: O %s A %s AS %s',
                    last.__class__,
                    getattr(last, 'options', None),
                    getattr(last, 'application', None),
                    getattr(last, 'applications', None))
      if hasattr(last, 'options'):
        last.options[key] = value

      # NOTE(termie): paste.urlmap.URLMap stores applications in this format
      if hasattr(last, 'applications'):
        for app in last.applications:
          applications.append(app[1])

      if hasattr(last, 'application'):
        last = last.application
      elif len(applications):
        last = applications.pop()
      else:
        break

  def client(self, app, *args, **kw):
    return TestClient(app, *args, **kw)

  def add_path(self, path):
    sys.path.insert(0, path)
    self._paths.append(path)

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
