# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the catalog interfaces

from keystonelight import utils


class Manager(object):
    def __init__(self, options):
        self.options = options
        self.driver = utils.import_object(options['catalog_driver'],
                                          options=options)

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
