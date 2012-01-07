# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the catalog interfaces

import uuid

from keystonelight import config
from keystonelight import utils


CONF = config.CONF


class Manager(object):
    def __init__(self):
        self.driver = utils.import_object(CONF.policy.driver)

    def can_haz(self, context, target, credentials):
        """Check whether the given creds can perform action on target."""
        return self.driver.can_haz(target, credentials)
