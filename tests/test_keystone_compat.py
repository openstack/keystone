import copy
import os
import json

from keystonelight import models
from keystonelight import test
from keystonelight import utils


IDENTITY_API_REPO = 'git://github.com/openstack/identity-api.git'


SAMPLE_DIR = 'openstack-identity-api/src/docbkx/samples'


cd = os.chdir


def checkout_samples(rev):
  """Make sure we have a checkout of the API docs."""
  revdir = os.path.join(test.VENDOR, 'identity-api-%s' % rev)

  if not os.path.exists(revdir):
    utils.git('clone', IDENTITY_API_REPO, revdir)

  cd(revdir)
  utils.git('pull')
  utils.git('checkout', rev)
  return revdir


class CompatTestCase(test.TestCase):
  def setUp(self):
    super(CompatTestCase, self).setUp()

    self.auth_creds = json.load(open(
        os.path.join(self.sampledir, 'auth_credentials.json')))
    self.auth_creds_notenant = copy.deepcopy(self.auth_creds)
    self.auth_creds_notenant['auth'].pop('tenantName', None)

    self.tenants_for_token = json.load(open(
        os.path.join(self.sampledir, 'tenants.json')))

    # For the tenants for token call
    self.user_foo = self.backend._create_user(
        'foo',
        models.User(id='foo', tenants=['1234', '3456']))
    self.tenant_1234 = self.backend._create_tenant(
        '1234',
        models.Tenant(id='1234',
                      name='ACME Corp',
                      description='A description...',
                      enabled=True))
    self.tenant_3456 = self.backend._create_tenant(
        '3456',
        models.Tenant(id='3456',
                      name='Iron Works',
                      description='A description...',
                      enabled=True))

    self.token_foo_unscoped = self.backend._create_token(
        'foo_unscoped',
        models.Token(id='foo_unscoped',
                     user='foo'))
    self.token_foo_scoped = self.backend._create_token(
        'foo_scoped',
        models.Token(id='foo_unscoped',
                     user='foo',
                     tenant='1234'))


class HeadCompatTestCase(CompatTestCase):
  def setUp(self):
    revdir = checkout_samples('HEAD')
    self.sampledir = os.path.join(revdir, SAMPLE_DIR)
    super(HeadCompatTestCase, self).setUp()

  def test_tenants_for_token_unscoped(self):
    # get_tenants_for_token
    client = self.api.client(token=self.token_foo_unscoped['id'])
    resp = client.get('/v2.0/tenants')
    data = json.loads(resp.body)
    self.assertDictEquals(self.tenants_for_token, data)

  def test_tenants_for_token_scoped(self):
    # get_tenants_for_token
    client = self.api.client(token=self.token_foo_scoped['id'])
    resp = client.get('/v2.0/tenants')
    data = json.loads(resp.body)
    self.assertDictEquals(self.tenants_for_token, data)
