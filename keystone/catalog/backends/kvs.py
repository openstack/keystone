# vim: tabstop=4 shiftwidth=4 softtabstop=4


from keystone.common import kvs


class Catalog(kvs.Base):
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
