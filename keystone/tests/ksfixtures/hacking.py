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

# NOTE(morganfainberg) This file shouldn't have flake8 run on it as it has
# code examples that will fail normal CI pep8/flake8 tests. This is expected.
# The code has been moved here to ensure that proper tests occur on the
# test_hacking_checks test cases.
# flake8: noqa

import fixtures


class HackingCode(fixtures.Fixture):
    """A fixture to house the various code examples for the keystone hacking
    style checks.
    """

    mutable_default_args = {
        'code': """
                def f():
                    pass

                def f(a, b='', c=None):
                    pass

                def f(bad=[]):
                    pass

                def f(foo, bad=[], more_bad=[x for x in range(3)]):
                    pass

                def f(foo, bad={}):
                    pass

                def f(foo, bad={}, another_bad=[], fine=None):
                    pass

                def f(bad=[]): # noqa
                    pass

            """,
        'expected_errors': [
            (7, 10, 'K001'),
            (10, 15, 'K001'),
            (10, 29, 'K001'),
            (13, 15, 'K001'),
            (16, 15, 'K001'),
            (16, 31, 'K001'),
        ]}

    comments_begin_with_space = {
        'code': """
            # This is a good comment

            #This is a bad one

            # This is alright and can
            #    be continued with extra indentation
            #    if that's what the developer wants.
        """,
        'expected_errors': [
            (3, 0, 'K002'),
        ]}

    asserting_none_equality = {
        'code': """
            class Test(object):

                def test(self):
                    self.assertEqual('', '')
                    self.assertEqual('', None)
                    self.assertEqual(None, '')
                    self.assertNotEqual('', None)
                    self.assertNotEqual(None, '')
                    self.assertNotEqual('', None) # noqa
                    self.assertNotEqual(None, '') # noqa
        """,
        'expected_errors': [
            (5, 8, 'K003'),
            (6, 8, 'K003'),
            (7, 8, 'K004'),
            (8, 8, 'K004'),
        ]}
