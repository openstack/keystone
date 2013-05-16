# Copyright 2013 IBM Corp.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.


from keystone.common import sql
from keystone import test


class TestBase(test.TestCase):

    def tearDown(self):
        sql.set_global_engine(None)
        super(TestBase, self).tearDown()

    def test_get_engine_global(self):
        # If call get_engine() twice, get the same global engine.
        base = sql.Base()
        engine1 = base.get_engine()
        self.assertIsNotNone(engine1)
        engine2 = base.get_engine()
        self.assertIs(engine1, engine2)

    def test_get_engine_not_global(self):
        # If call get_engine() twice, once with allow_global_engine=True
        # and once with allow_global_engine=False, get different engines.
        base = sql.Base()
        engine1 = base.get_engine()
        engine2 = base.get_engine(allow_global_engine=False)
        self.assertIsNot(engine1, engine2)
