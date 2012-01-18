# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the Identity service."""

from keystone import config
from keystone import manager


CONF = config.CONF


class Manager(manager.Manager):
    """Default pivot point for the Identity backend.

    See :mod:`keystone.manager.Manager` for more details.
    """
    def __init__(self):
        super(Manager, self).__init__(CONF.identity.driver)
