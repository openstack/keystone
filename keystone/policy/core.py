# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the Policy service."""

from keystone import config
from keystone.common import manager


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.policy.driver)
