# vim: tabstop=4 shiftwidth=4 softtabstop=4


from keystone.common import logging


class TrivialTrue(object):
    def can_haz(self, target, credentials):
        return True


class SimpleMatch(object):
    def can_haz(self, target, credentials):
        """Check whether key-values in target are present in credentials."""
        # TODO(termie): handle ANDs, probably by providing a tuple instead of a
        #               string
        for requirement in target:
            key, match = requirement.split(':', 1)
            check = credentials.get(key)
            if check == match:
                return True
