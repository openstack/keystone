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

  def get_role(self, context, role_id):
    return self.driver.get_role(role_id)

  # NOTE(termie): i think it will probably be a bad move in the end to try to
  #               list all users
  def list_users(self, context):
    return self.driver.list_users()

  # These should probably be the high-level API calls
  def add_user_to_tenant(self, context, user_id, tenant_id):
    self.driver.add_user_to_tenant(user_id, tenant_id)

  def remove_user_from_tenant(self, context, user_id, tenant_id):
    self.driver.remove_user_from_tenant(user_id, tenant_id)

  def get_tenants_for_user(self, context, user_id):
    return self.driver.get_tenants_for_user(user_id)

  def get_roles_for_user_and_tenant(self, context, user_id, tenant_id):
    return self.driver.get_roles_for_user_and_tenant(user_id, tenant_id)

  def add_role_to_user_and_tenant(self, context, user_id, tenant_id, role_id):
    return self.driver.add_role_to_user_and_tenant(user_id, tenant_id, role_id)

  def remove_role_from_user_and_tenant(self, context, user_id,
                                      tenant_id, role_id):
    return self.driver.remove_role_from_user_and_tenant(
        user_id, tenant_id, role_id)

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

  def create_role(self, context, role_id, data):
    return self.driver.create_role(role_id, data)

  def update_role(self, context, role_id, data):
    return self.driver.update_role(role_id, data)

  def delete_role(self, context, role_id):
    return self.driver.delete_role(role_id)
