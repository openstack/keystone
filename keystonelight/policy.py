# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the catalog interfaces

import uuid

from keystonelight import utils


class Manager(object):
    def __init__(self, options):
        self.options = options
        self.driver = utils.import_object(options['policy_driver'],
                                          options=options)

    def can_haz(self, context, target, credentials):
        """Check whether the given creds can perform action on target."""
        return self.driver.can_haz(target, credentials)
