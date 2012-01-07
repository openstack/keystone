class IdentityTests(object):
  def test_authenticate_bad_user(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'] + 'WRONG',
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'])

  def test_authenticate_bad_password(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'] + 'WRONG')

  def test_authenticate_invalid_tenant(self):
    self.assertRaises(AssertionError,
        self.identity_api.authenticate,
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'] + 'WRONG',
        password=self.user_foo['password'])

  def test_authenticate_no_tenant(self):
    user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
        user_id=self.user_foo['id'],
        password=self.user_foo['password'])
    self.assertDictEquals(user_ref, self.user_foo)
    self.assert_(tenant_ref is None)
    self.assert_(not extras_ref)

  def test_authenticate(self):
    user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'],
        password=self.user_foo['password'])
    self.assertDictEquals(user_ref, self.user_foo)
    self.assertDictEquals(tenant_ref, self.tenant_bar)
    self.assertDictEquals(extras_ref, self.extras_foobar)

  def test_get_tenant_bad_tenant(self):
    tenant_ref = self.identity_api.get_tenant(
        tenant_id=self.tenant_bar['id'] + 'WRONG')
    self.assert_(tenant_ref is None)

  def test_get_tenant(self):
    tenant_ref = self.identity_api.get_tenant(tenant_id=self.tenant_bar['id'])
    self.assertDictEquals(tenant_ref, self.tenant_bar)

  def test_get_tenant_by_name_bad_tenant(self):
    tenant_ref = self.identity_api.get_tenant(
        tenant_id=self.tenant_bar['name'] + 'WRONG')
    self.assert_(tenant_ref is None)

  def test_get_tenant_by_name(self):
    tenant_ref = self.identity_api.get_tenant_by_name(
        tenant_name=self.tenant_bar['name'])
    self.assertDictEquals(tenant_ref, self.tenant_bar)

  def test_get_user_bad_user(self):
    user_ref = self.identity_api.get_user(
        user_id=self.user_foo['id'] + 'WRONG')
    self.assert_(user_ref is None)

  def test_get_user(self):
    user_ref = self.identity_api.get_user(user_id=self.user_foo['id'])
    self.assertDictEquals(user_ref, self.user_foo)

  def test_get_extras_bad_user(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'] + 'WRONG',
        tenant_id=self.tenant_bar['id'])
    self.assert_(extras_ref is None)

  def test_get_extras_bad_tenant(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'] + 'WRONG')
    self.assert_(extras_ref is None)

  def test_get_extras(self):
    extras_ref = self.identity_api.get_extras(
        user_id=self.user_foo['id'],
        tenant_id=self.tenant_bar['id'])
    self.assertDictEquals(extras_ref, self.extras_foobar)

  def test_get_role(self):
    role_ref = self.identity_api.get_role(
        role_id=self.role_keystone_admin['id'])
    self.assertDictEquals(role_ref, self.role_keystone_admin)


