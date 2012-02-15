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
            if check is None or isinstance(check, basestring):
                check = [check]
            if match in check:
                return True
