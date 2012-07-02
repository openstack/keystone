# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Helper module for systemd start-up completion notification.
Used for "onready" configuration parameter in keystone.conf
"""

import os
import socket


def _sd_notify(msg):
    sysd = os.getenv('NOTIFY_SOCKET')
    if sysd:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(sysd)
        sock.sendall(msg)
        sock.close()


def notify():
    _sd_notify('READY=1')


if __name__ == '__main__':
    notify()
