# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

_FATAL_EXCEPTION_FORMAT_ERRORS = False


class KdsException(Exception):
    """Base Exception class.

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    msg_fmt = _('An unknown exception occurred')

    def __init__(self, **kwargs):
        try:
            self._error_string = self.msg_fmt % kwargs

        except Exception:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                # at least get the core message out if something happened
                self._error_string = self.msg_fmt

    def __str__(self):
        return self._error_string


class BackendException(KdsException):
    msg_fmt = _("Failed to load the '%(backend)s' backend because it is not "
                "allowed. Allowed backends are: %(allowed)s")


class IntegrityError(KdsException):
    msg_fmt = _('Cannot set key data for %(name)s: %(reason)s')


class GroupStatusChanged(IntegrityError):

    def __init__(self, **kwargs):
        kwargs.setdefault('reason', "Can't change group status of a host")
        super(GroupStatusChanged, self).__init__(**kwargs)
