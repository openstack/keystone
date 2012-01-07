# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the catalog interfaces

from keystonelight import config
from keystonelight import utils


CONF = config.CONF


class Manager(object):
    def __init__(self):
        self.driver = utils.import_object(CONF.catalog.driver)

    def get_catalog(self, context, user_id, tenant_id, extras=None):
        """Return info for a catalog if it is valid."""
        return self.driver.get_catalog(user_id, tenant_id, extras=extras)

    def get_service(self, context, service_id):
        return self.driver.get_service(service_id)

    def list_services(self, context):
        return self.driver.list_services()

    def create_service(self, context, service_id, data):
        return self.driver.create_service(service_id, data)

    def delete_service(self, context, service_id):
        return self.driver.delete_service(service_id)
