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

import textwrap

import mock
import pep8
import testtools

from keystone.hacking import checks


class BaseStyleCheck(testtools.TestCase):

    def get_checker(self):
        """Returns the checker to be used for tests in this class."""
        raise NotImplemented('subclasses must provide a real implementation')

    # We are patching pep8 so that only the check under test is actually
    # installed.
    @mock.patch('pep8._checks',
                {'physical_line': {}, 'logical_line': {}, 'tree': {}})
    def run_check(self, code):
        pep8.register_check(self.get_checker())

        lines = textwrap.dedent(code).strip().splitlines(True)

        checker = pep8.Checker(lines=lines)
        checker.check_all()
        checker.report._deferred_print.sort()
        return checker.report._deferred_print

    def assert_has_errors(self, code, expected_errors=None):
        actual_errors = [e[:3] for e in self.run_check(code)]
        self.assertEqual(expected_errors or [], actual_errors)


class TestCheckForMutableDefaultArgs(BaseStyleCheck):

    def get_checker(self):
        return checks.CheckForMutableDefaultArgs

    def test(self):
        code = """
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

            def f(bad=[]):  # noqa
                pass

        """
        expected_errors = [
            (7, 10, 'K001'),
            (10, 15, 'K001'),
            (10, 29, 'K001'),
            (13, 15, 'K001'),
            (16, 15, 'K001'),
            (16, 31, 'K001'),
        ]
        self.assert_has_errors(code, expected_errors=expected_errors)


class TestBlockCommentsBeginWithASpace(BaseStyleCheck):

    def get_checker(self):
        return checks.block_comments_begin_with_a_space

    def test(self):
        # NOTE(dstanek): The 'noqa' line below will stop the normal CI
        # pep8 process from flaging an error when running against this code.
        # The unit tests use pep8 directly and the 'noqa' has no effect so we
        # can easilty test.
        code = """
            # This is a good comment

            #This is a bad one        # flake8: noqa

            # This is alright and can
            #    be continued with extra indentation
            #    if that's what the developer wants.
        """
        self.assert_has_errors(code, [(3, 0, 'K002')])


class TestAssertingNoneEquality(BaseStyleCheck):

    def get_checker(self):
        return checks.CheckForAssertingNoneEquality

    def test(self):
        code = """
            class Test(object):

                def test(self):
                    self.assertEqual('', '')
                    self.assertEqual('', None)
                    self.assertEqual(None, '')
                    self.assertNotEqual('', None)
                    self.assertNotEqual(None, '')
                    self.assertNotEqual('', None)  # noqa
                    self.assertNotEqual(None, '')  # noqa
        """
        expected_errors = [
            (5, 8, 'K003'),
            (6, 8, 'K003'),
            (7, 8, 'K004'),
            (8, 8, 'K004'),
        ]
        self.assert_has_errors(code, expected_errors=expected_errors)
