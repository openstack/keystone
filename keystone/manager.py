# vim: tabstop=4 shiftwidth=4 softtabstop=4

import functools

from keystone import config
from keystone import utils


class Manager(object):
    def __init__(self, driver_name):
        self.driver = utils.import_object(driver_name)

    def __getattr__(self, name):
        # NOTE(termie): context is the first argument, we're going to strip
        #               that for now, in the future we'll probably do some
        #               logging and whatnot in this class
        f = getattr(self.driver, name)

        @functools.wraps(f)
        def _wrapper(context, *args, **kw):
            return f(*args, **kw)
        setattr(self, name, _wrapper)
        return _wrapper
