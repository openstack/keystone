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

import pycodestyle

from keystone.tests.hacking import checks
from keystone.tests import unit
from keystone.tests.unit.ksfixtures import hacking as hacking_fixtures


class BaseStyleCheck(unit.BaseTestCase):

    def setUp(self):
        super(BaseStyleCheck, self).setUp()
        self.code_ex = self.useFixture(self.get_fixture())
        self.addCleanup(delattr, self, 'code_ex')

    def get_checker(self):
        """Return the checker to be used for tests in this class."""
        raise NotImplementedError('subclasses must provide '
                                  'a real implementation')

    def get_fixture(self):
        return hacking_fixtures.HackingCode()

    def run_check(self, code):
        pycodestyle.register_check(self.get_checker())

        lines = textwrap.dedent(code).strip().splitlines(True)

        # Load all keystone hacking checks, they are of the form Kddd,
        # where ddd can from range from 000-999
        guide = pycodestyle.StyleGuide(select='K')
        checker = pycodestyle.Checker(lines=lines, options=guide.options)
        checker.check_all()
        checker.report._deferred_print.sort()
        return checker.report._deferred_print

    def assert_has_errors(self, code, expected_errors=None):
        actual_errors = [e[:3] for e in self.run_check(code)]
        self.assertCountEqual(expected_errors or [], actual_errors)


class TestCheckForMutableDefaultArgs(BaseStyleCheck):

    def get_checker(self):
        return checks.CheckForMutableDefaultArgs

    def test(self):
        code = self.code_ex.mutable_default_args['code']
        errors = self.code_ex.mutable_default_args['expected_errors']
        self.assert_has_errors(code, expected_errors=errors)


class TestBlockCommentsBeginWithASpace(BaseStyleCheck):

    def get_checker(self):
        return checks.block_comments_begin_with_a_space

    def test(self):
        code = self.code_ex.comments_begin_with_space['code']
        errors = self.code_ex.comments_begin_with_space['expected_errors']
        self.assert_has_errors(code, expected_errors=errors)


class TestTranslationChecks(BaseStyleCheck):

    def get_checker(self):
        return checks.CheckForTranslationIssues

    def get_fixture(self):
        return hacking_fixtures.HackingTranslations()

    def assert_has_errors(self, code, expected_errors=None):
        # pull out the parts of the error that we'll match against
        actual_errors = (e[:3] for e in self.run_check(code))
        # adjust line numbers to make the fixture data more readable.
        import_lines = len(self.code_ex.shared_imports.split('\n')) - 1
        actual_errors = [(e[0] - import_lines, e[1], e[2])
                         for e in actual_errors]
        self.assertEqual(expected_errors or [], actual_errors)

    def test_for_translations(self):
        for example in self.code_ex.examples:
            code = self.code_ex.shared_imports + example['code']
            errors = example['expected_errors']
            self.assert_has_errors(code, expected_errors=errors)


class TestDictConstructorWithSequenceCopy(BaseStyleCheck):

    def get_checker(self):
        return checks.dict_constructor_with_sequence_copy

    def test(self):
        code = self.code_ex.dict_constructor['code']
        errors = self.code_ex.dict_constructor['expected_errors']
        self.assert_has_errors(code, expected_errors=errors)
