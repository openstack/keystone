# these will be the basic data types for tenants and users
# backends will make use of them to return something that conforms to their
# apis


from keystonelight import utils


class Manager(object):
  def __init__(self, options):
    self.driver = utils.import_object(options['identity_driver'],
                                      options=options)
    self.options = options

  def authenticate(self, context, **kwargs):
    """Passthru authentication to the identity driver.

    This call will basically just result in getting a token.
    """
    return self.driver.authenticate(**kwargs)

  def get_user(self, context, user_id):
    return self.driver.get_user(user_id)

  def get_user_by_name(self, context, user_name):
    return self.driver.get_user_by_name(user_name)

  def get_tenant(self, context, tenant_id):
    return self.driver.get_tenant(tenant_id)

  def get_tenant_by_name(self, context, tenant_name):
    return self.driver.get_tenant_by_name(tenant_name)

  def get_extras(self, context, user_id, tenant_id):
    return self.driver.get_extras(user_id, tenant_id)

  # CRUD operations
  def create_user(self, context, user_id, data):
    return self.driver.create_user(user_id, data)

  def update_user(self, context, user_id, data):
    return self.driver.update_user(user_id, data)

  def delete_user(self, context, user_id):
    return self.driver.delete_user(user_id)

  def create_tenant(self, context, tenant_id, data):
    return self.driver.create_tenant(tenant_id, data)

  def update_tenant(self, context, tenant_id, data):
    return self.driver.update_tenant(tenant_id, data)

  def delete_tenant(self, context, tenant_id):
    return self.driver.delete_tenant(tenant_id)

  def create_extras(self, context, user_id, tenant_id, data):
    return self.driver.create_extras(user_id, tenant_id, data)

  def update_extras(self, context, user_id, tenant_id, data):
    return self.driver.update_extras(user_id, tenant_id, data)

  def delete_extras(self, context, user_id, tenant_id):
    return self.driver.delete_extras(user_id, tenant_id)
