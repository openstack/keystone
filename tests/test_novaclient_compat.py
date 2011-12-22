import copy
import json
import os
import sys

from keystonelight import logging
from keystonelight import models
from keystonelight import test
from keystonelight import utils


NOVACLIENT_REPO = 'git://github.com/openstack/python-novaclient.git'


class CompatTestCase(test.TestCase):
  def setUp(self):
    super(CompatTestCase, self).setUp()


class NovaClientCompatMasterTestCase(CompatTestCase):
  def setUp(self):
    super(NovaClientCompatMasterTestCase, self).setUp()

    revdir = test.checkout_vendor(NOVACLIENT_REPO, 'master')
    self.add_path(revdir)
    from novaclient.keystone import client as ks_client
    from novaclient import client as base_client
    reload(ks_client)
    reload(base_client)

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


  def test_authenticate_and_tenants(self):
    from novaclient.keystone import client as ks_client
    from novaclient import client as base_client

    port = self.server.socket_info['socket'][1]
    self.options['public_port'] = port

    # NOTE(termie): novaclient wants a "/" TypeErrorat the end, keystoneclient does not
    # NOTE(termie): projectid is apparently sent as tenantName, so... that's
    #               unfortunate.
    # NOTE(termie): novaclient seems to care about the region more than
    #               keystoneclient
    conn = base_client.HTTPClient(auth_url="http://localhost:%s/v2.0/" % port,
                                  user='FOO',
                                  password='foo',
                                  projectid='BAR',
                                  region_name='RegionOne')
    client = ks_client.Client(conn)
    client.authenticate()
    # NOTE(termie): novaclient doesn't know about tenants or anything like that
    #               so just test that we can validate
