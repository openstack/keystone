# vim: tabstop=4 shiftwidth=4 softtabstop=4


class DictKvs(dict):
    def set(self, key, value):
        self[key] = value

    def delete(self, key):
        del self[key]


INMEMDB = DictKvs()


class KvsIdentity(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db

    # Public interface
    def authenticate(self, user_id=None, tenant_id=None, password=None):
        """Authenticate based on a user, tenant and password.

        Expects the user object to have a password field and the tenant to be
        in the list of tenants on the user.

        """
        user_ref = self.get_user(user_id)
        tenant_ref = None
        metadata_ref = None
        if not user_ref or user_ref.get('password') != password:
            raise AssertionError('Invalid user / password')
        if tenant_id and tenant_id not in user_ref['tenants']:
            raise AssertionError('Invalid tenant')

        tenant_ref = self.get_tenant(tenant_id)
        if tenant_ref:
            metadata_ref = self.get_metadata(user_id, tenant_id)
        else:
            metadata_ref = {}
        return (user_ref, tenant_ref, metadata_ref)

    def get_tenant(self, tenant_id):
        tenant_ref = self.db.get('tenant-%s' % tenant_id)
        return tenant_ref

    def get_tenant_by_name(self, tenant_name):
        tenant_ref = self.db.get('tenant_name-%s' % tenant_name)
        return tenant_ref

    def get_user(self, user_id):
        user_ref = self.db.get('user-%s' % user_id)
        return user_ref

    def get_user_by_name(self, user_name):
        user_ref = self.db.get('user_name-%s' % user_name)
        return user_ref

    def get_metadata(self, user_id, tenant_id):
        return self.db.get('metadata-%s-%s' % (tenant_id, user_id))

    def get_role(self, role_id):
        role_ref = self.db.get('role-%s' % role_id)
        return role_ref

    def list_users(self):
        user_ids = self.db.get('user_list', [])
        return [self.get_user(x) for x in user_ids]

    def list_roles(self):
        role_ids = self.db.get('role_list', [])
        return [self.get_role(x) for x in role_ids]

    # These should probably be part of the high-level API
    def add_user_to_tenant(self, tenant_id, user_id):
        user_ref = self.get_user(user_id)
        tenants = set(user_ref.get('tenants', []))
        tenants.add(tenant_id)
        user_ref['tenants'] = list(tenants)
        self.update_user(user_id, user_ref)

    def remove_user_from_tenant(self, tenant_id, user_id):
        user_ref = self.get_user(user_id)
        tenants = set(user_ref.get('tenants', []))
        tenants.remove(tenant_id)
        user_ref['tenants'] = list(tenants)
        self.update_user(user_id, user_ref)

    def get_tenants_for_user(self, user_id):
        user_ref = self.get_user(user_id)
        return user_ref.get('tenants', [])

    def get_roles_for_user_and_tenant(self, user_id, tenant_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        return metadata_ref.get('roles', [])

    def add_role_to_user_and_tenant(self, user_id, tenant_id, role_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        roles = set(metadata_ref.get('roles', []))
        roles.add(role_id)
        metadata_ref['roles'] = list(roles)
        self.update_metadata(user_id, tenant_id, metadata_ref)

    def remove_role_from_user_and_tenant(self, user_id, tenant_id, role_id):
        metadata_ref = self.get_metadata(user_id, tenant_id)
        if not metadata_ref:
            metadata_ref = {}
        roles = set(metadata_ref.get('roles', []))
        roles.remove(role_id)
        metadata_ref['roles'] = list(roles)
        self.update_metadata(user_id, tenant_id, metadata_ref)

    # CRUD
    def create_user(self, user_id, user):
        self.db.set('user-%s' % user_id, user)
        self.db.set('user_name-%s' % user['name'], user)
        user_list = set(self.db.get('user_list', []))
        user_list.add(user_id)
        self.db.set('user_list', list(user_list))
        return user

    def update_user(self, user_id, user):
        # get the old name and delete it too
        old_user = self.db.get('user-%s' % user_id)
        self.db.delete('user_name-%s' % old_user['name'])
        self.db.set('user-%s' % user_id, user)
        self.db.set('user_name-%s' % user['name'], user)
        return user

    def delete_user(self, user_id):
        old_user = self.db.get('user-%s' % user_id)
        self.db.delete('user_name-%s' % old_user['name'])
        self.db.delete('user-%s' % user_id)
        user_list = set(self.db.get('user_list', []))
        user_list.remove(user_id)
        self.db.set('user_list', list(user_list))
        return None

    def create_tenant(self, tenant_id, tenant):
        self.db.set('tenant-%s' % tenant_id, tenant)
        self.db.set('tenant_name-%s' % tenant['name'], tenant)
        return tenant

    def update_tenant(self, tenant_id, tenant):
        # get the old name and delete it too
        old_tenant = self.db.get('tenant-%s' % tenant_id)
        self.db.delete('tenant_name-%s' % old_tenant['name'])
        self.db.set('tenant-%s' % tenant_id, tenant)
        self.db.set('tenant_name-%s' % tenant['name'], tenant)
        return tenant

    def delete_tenant(self, tenant_id):
        old_tenant = self.db.get('tenant-%s' % tenant_id)
        self.db.delete('tenant_name-%s' % old_tenant['name'])
        self.db.delete('tenant-%s' % tenant_id)
        return None

    def create_metadata(self, user_id, tenant_id, metadata):
        self.db.set('metadata-%s-%s' % (tenant_id, user_id), metadata)
        return metadata

    def update_metadata(self, user_id, tenant_id, metadata):
        self.db.set('metadata-%s-%s' % (tenant_id, user_id), metadata)
        return metadata

    def delete_metadata(self, user_id, tenant_id):
        self.db.delete('metadata-%s-%s' % (tenant_id, user_id))
        return None

    def create_role(self, role_id, role):
        self.db.set('role-%s' % role_id, role)
        role_list = set(self.db.get('role_list', []))
        role_list.add(role_id)
        self.db.set('role_list', list(role_list))
        return role

    def update_role(self, role_id, role):
        self.db.set('role-%s' % role_id, role)
        return role

    def delete_role(self, role_id):
        self.db.delete('role-%s' % role_id)
        role_list = set(self.db.get('role_list', []))
        role_list.remove(role_id)
        self.db.set('role_list', list(role_list))
        return None


class KvsToken(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db

    # Public interface
    def get_token(self, token_id):
        return self.db.get('token-%s' % token_id)

    def create_token(self, token_id, data):
        self.db.set('token-%s' % token_id, data)
        return data

    def delete_token(self, token_id):
        return self.db.delete('token-%s' % token_id)


class KvsCatalog(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db

    # Public interface
    def get_catalog(self, user_id, tenant_id, metadata=None):
        return self.db.get('catalog-%s-%s' % (tenant_id, user_id))

    def get_service(self, service_id):
        return self.db.get('service-%s' % service_id)

    def list_services(self):
        return self.db.get('service_list', [])

    def create_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        service_list = set(self.db.get('service_list', []))
        service_list.add(service_id)
        self.db.set('service_list', list(service_list))
        return service

    def update_service(self, service_id, service):
        self.db.set('service-%s' % service_id, service)
        return service

    def delete_service(self, service_id):
        self.db.delete('service-%s' % service_id)
        service_list = set(self.db.get('service_list', []))
        service_list.remove(service_id)
        self.db.set('service_list', list(service_list))
        return None

    # Private interface
    def _create_catalog(self, user_id, tenant_id, data):
        self.db.set('catalog-%s-%s' % (tenant_id, user_id), data)
        return data


class KvsPolicy(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db

    def can_haz(self, target, action, credentials):
        pass


class KvsEc2(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db

    # Public interface
    def get_credential(self, credential_id):
        credential_ref = self.db.get('credential-%s' % credential_id)
        return credential_ref

    def list_credentials(self, user_id):
        credential_ids = self.db.get('credential_list', [])
        rv = [self.get_credential(x) for x in credential_ids]
        return [x for x in rv if x['user_id'] == user_id]

    # CRUD
    def create_credential(self, credential_id, credential):
        self.db.set('credential-%s' % credential_id, credential)
        credential_list = set(self.db.get('credential_list', []))
        credential_list.add(credential_id)
        self.db.set('credential_list', list(credential_list))
        return credential

    def delete_credential(self, credential_id):
        old_credential = self.db.get('credential-%s' % credential_id)
        self.db.delete('credential-%s' % credential_id)
        credential_list = set(self.db.get('credential_list', []))
        credential_list.remove(credential_id)
        self.db.set('credential_list', list(credential_list))
        return None
