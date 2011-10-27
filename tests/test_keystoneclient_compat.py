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


class DiabloCompatTestCase(CompatTestCase):
  def setUp(self):
    revdir = test.checkout_vendor(KEYSTONECLIENT_REPO, 'master')
    self.add_path(revdir)
    from keystoneclient.v2_0 import client as ks_client
    reload(ks_client)

    self.app = self.loadapp('keystone_compat_diablo')
    self.options = self.appconfig('keystone_compat_diablo')

    self.identity_backend = utils.import_object(
        self.options['identity_driver'], options=self.options)
    self.token_backend = utils.import_object(
        self.options['token_driver'], options=self.options)
    self.catalog_backend = utils.import_object(
        self.options['catalog_driver'], options=self.options)

    super(DiabloCompatTestCase, self).setUp()

  def test_pass(self):
    pass
