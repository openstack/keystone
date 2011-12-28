# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
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

""" Client Tests

Client tests are tests that use HTTP(S) calls to a Keystone server to exercise
request/response test cases.

In order to avoid port conflicts,  client tests use the global settings below
to know which server to talk to.

When a server is started for testing purposes (usually by the
keystone.test.KeystoneTest class) it will update these values so client tests
know where to find the server

"""
TEST_TARGET_SERVER_ADMIN_PROTOCOL = 'http'
TEST_TARGET_SERVER_ADMIN_ADDRESS = '127.0.0.1'
TEST_TARGET_SERVER_ADMIN_PORT = 35357

TEST_TARGET_SERVER_SERVICE_PROTOCOL = 'http'
TEST_TARGET_SERVER_SERVICE_ADDRESS = '127.0.0.1'
TEST_TARGET_SERVER_SERVICE_PORT = 5000

TEST_CONFIG_FILE_NAME = None
