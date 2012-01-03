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
