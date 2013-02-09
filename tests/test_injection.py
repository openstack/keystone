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

import unittest2 as unittest
import uuid

from keystone.common import dependency


class TestDependencyInjection(unittest.TestCase):
    def test_dependency_injection(self):
        class Interface(object):
            def do_work(self):
                assert False

        @dependency.provider('first_api')
        class FirstImplementation(Interface):
            def do_work(self):
                return True

        @dependency.provider('second_api')
        class SecondImplementation(Interface):
            def do_work(self):
                return True

        @dependency.requires('first_api', 'second_api')
        class Consumer(object):
            def do_work_with_dependencies(self):
                assert self.first_api.do_work()
                assert self.second_api.do_work()

        # initialize dependency providers
        first_api = FirstImplementation()
        second_api = SecondImplementation()

        # ... sometime later, initialize a dependency consumer
        consumer = Consumer()

        # the expected dependencies should be available to the consumer
        self.assertIs(consumer.first_api, first_api)
        self.assertIs(consumer.second_api, second_api)
        self.assertIsInstance(consumer.first_api, Interface)
        self.assertIsInstance(consumer.second_api, Interface)
        consumer.do_work_with_dependencies()

    def test_dependency_provider_configuration(self):
        @dependency.provider('api')
        class Configurable(object):
            def __init__(self, value=None):
                self.value = value

            def get_value(self):
                return self.value

        @dependency.requires('api')
        class Consumer(object):
            def get_value(self):
                return self.api.get_value()

        # initialize dependency providers
        api = Configurable(value=True)

        # ... sometime later, initialize a dependency consumer
        consumer = Consumer()

        # the expected dependencies should be available to the consumer
        self.assertIs(consumer.api, api)
        self.assertIsInstance(consumer.api, Configurable)
        self.assertTrue(consumer.get_value())

    def test_dependency_consumer_configuration(self):
        @dependency.provider('api')
        class Provider(object):
            def get_value(self):
                return True

        @dependency.requires('api')
        class Configurable(object):
            def __init__(self, value=None):
                self.value = value

            def get_value(self):
                if self.value:
                    return self.api.get_value()

        # initialize dependency providers
        api = Provider()

        # ... sometime later, initialize a dependency consumer
        consumer = Configurable(value=True)

        # the expected dependencies should be available to the consumer
        self.assertIs(consumer.api, api)
        self.assertIsInstance(consumer.api, Provider)
        self.assertTrue(consumer.get_value())

    def test_inherited_dependency(self):
        class Interface(object):
            def do_work(self):
                assert False

        @dependency.provider('first_api')
        class FirstImplementation(Interface):
            def do_work(self):
                return True

        @dependency.provider('second_api')
        class SecondImplementation(Interface):
            def do_work(self):
                return True

        @dependency.requires('first_api')
        class ParentConsumer(object):
            def do_work_with_dependencies(self):
                assert self.first_api.do_work()

        @dependency.requires('second_api')
        class ChildConsumer(ParentConsumer):
            def do_work_with_dependencies(self):
                assert self.second_api.do_work()
                super(ChildConsumer, self).do_work_with_dependencies()

        # initialize dependency providers
        first_api = FirstImplementation()
        second_api = SecondImplementation()

        # ... sometime later, initialize a dependency consumer
        consumer = ChildConsumer()

        # dependencies should be naturally inherited
        self.assertEqual(
            ParentConsumer._dependencies,
            set(['first_api']))
        self.assertEqual(
            ChildConsumer._dependencies,
            set(['first_api', 'second_api']))
        self.assertEqual(
            consumer._dependencies,
            set(['first_api', 'second_api']))

        # the expected dependencies should be available to the consumer
        self.assertIs(consumer.first_api, first_api)
        self.assertIs(consumer.second_api, second_api)
        self.assertIsInstance(consumer.first_api, Interface)
        self.assertIsInstance(consumer.second_api, Interface)
        consumer.do_work_with_dependencies()

    def test_unresolvable_dependency(self):
        @dependency.requires(uuid.uuid4().hex)
        class Consumer(object):
            pass

        with self.assertRaises(dependency.UnresolvableDependencyException):
            Consumer()
