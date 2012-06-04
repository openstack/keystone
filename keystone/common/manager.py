# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools

from keystone.openstack.common import importutils


class Manager(object):
    """Base class for intermediary request layer.

    The Manager layer exists to support additional logic that applies to all
    or some of the methods exposed by a service that are not specific to the
    HTTP interface.

    It also provides a stable entry point to dynamic backends.

    An example of a probable use case is logging all the calls.

    """

    def __init__(self, driver_name):
        self.driver = importutils.import_object(driver_name)

    def __getattr__(self, name):
        """Forward calls to the underlying driver."""
        # NOTE(termie): context is the first argument, we're going to strip
        #               that for now, in the future we'll probably do some
        #               logging and whatnot in this class
        f = getattr(self.driver, name)

        @functools.wraps(f)
        def _wrapper(context, *args, **kw):
            return f(*args, **kw)
        setattr(self, name, _wrapper)
        return _wrapper
