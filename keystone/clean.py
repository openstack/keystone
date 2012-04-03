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

from keystone import exception


def check_length(property_name, value, min_length=1, max_length=64):
    if len(value) < min_length:
        if min_length == 1:
            msg = "%s cannot be empty." % property_name
        else:
            msg = ("%(property_name)s cannot be less than "
                   "%(min_length)s characters.") % locals()
        raise exception.ValidationError(msg)
    if len(value) > max_length:
        msg = ("%(property_name)s should not be greater than "
               "%(max_length)s characters.") % locals()
        raise exception.ValidationError(msg)


def check_type(property_name, value, expected_type, display_expected_type):
    if not isinstance(value, expected_type):
        msg = "%(property_name)s is not a %(display_expected_type)s" % locals()
        raise exception.ValidationError(msg)


def tenant_name(name):
    check_type("Tenant name", name, basestring, "string or unicode")
    name = name.strip()
    check_length("Tenant name", name)
    return name
