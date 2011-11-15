import copy
import json
import os
import sys

from keystonelight import logging
from keystonelight import models
from keystonelight import test
from keystonelight import utils


KEYSTONECLIENT_REPO = 'git://github.com/4P/python-keystoneclient.git'



class CompatTestCase(test.TestCase):
  def setUp(self):
    super(CompatTestCase, self).setUp()


class MasterCompatTestCase(CompatTestCase):
  def setUp(self):
    super(MasterCompatTestCase, self).setUp()

    revdir = test.checkout_vendor(KEYSTONECLIENT_REPO, 'master')
    self.add_path(revdir)
    from keystoneclient.v2_0 import client as ks_client
    reload(ks_client)

    self.app = self.loadapp('keystoneclient_compat_master')
    self.options = self.appconfig('keystoneclient_compat_master')

    self.identity_backend = utils.import_object(
        self.options['identity_driver'], options=self.options)
    self.token_backend = utils.import_object(
        self.options['token_driver'], options=self.options)
    self.catalog_backend = utils.import_object(
        self.options['catalog_driver'], options=self.options)

    self.server = self.serveapp('keystoneclient_compat_master')

    self.tenant_bar = self.identity_backend.create_tenant(
        'bar',
        models.Tenant(id='bar', name='BAR'))

    self.user_foo = self.identity_backend.create_user(
        'foo',
        models.User(id='foo',
                    name='FOO',
                    tenants=[self.tenant_bar['id']],
                    password='foo'))

    self.extras_bar_foo = self.identity_backend.create_extras(
        self.user_foo['id'], self.tenant_bar['id'],
        dict(roles=[],
             roles_links=[]))

  #def test_authenticate(self):
  #  from keystoneclient.v2_0 import client as ks_client

  #  port = self.server.socket_info['socket'][1]
  #  client = ks_client.Client(auth_url="http://localhost:%s/v2.0" % port,
  #                            username='foo',
  #                            password='foo',
  #                            project_id='bar')
  #  client.authenticate()

  def test_authenticate_and_tenants(self):
    from keystoneclient.v2_0 import client as ks_client

    port = self.server.socket_info['socket'][1]
    self.options['public_port'] = port
    # NOTE(termie): novaclient wants a "/" at the end, keystoneclient does not
    client = ks_client.Client(auth_url="http://localhost:%s/v2.0/" % port,
                              username='FOO',
                              password='foo',
                              project_id='bar')
    client.authenticate()
    tenants = client.tenants.list()
    self.assertEquals(tenants[0].id, self.tenant_bar['id'])
