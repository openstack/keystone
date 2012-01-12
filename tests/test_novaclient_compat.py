import copy
import json
import os
import sys

from keystone import config
from keystone import logging
from keystone import test
from keystone import utils

import default_fixtures


CONF = config.CONF
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

    CONF(config_files=[test.etcdir('keystone.conf'),
                       test.testsdir('test_overrides.conf')])
    self.app = self.loadapp('keystone')
    self.load_backends()
    self.load_fixtures(default_fixtures)
    self.server = self.serveapp('keystone')

  def test_authenticate_and_tenants(self):
    from novaclient.keystone import client as ks_client
    from novaclient import client as base_client

    port = self.server.socket_info['socket'][1]
    CONF.public_port = port

    # NOTE(termie): novaclient wants a "/" TypeErrorat the end, keystoneclient does not
    # NOTE(termie): projectid is apparently sent as tenantName, so... that's
    #               unfortunate.
    # NOTE(termie): novaclient seems to care about the region more than
    #               keystoneclient
    conn = base_client.HTTPClient(auth_url="http://localhost:%s/v2.0/" % port,
                                  user='FOO',
                                  password='foo2',
                                  projectid='BAR',
                                  region_name='RegionOne')
    client = ks_client.Client(conn)
    client.authenticate()
    # NOTE(termie): novaclient doesn't know about tenants or anything like that
    #               so just test that we can validate
