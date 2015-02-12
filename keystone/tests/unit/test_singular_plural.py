# Copyright 2012 Red Hat, Inc.
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

import ast

from keystone.contrib.admin_crud import core as admin_crud_core
from keystone.contrib.s3 import core as s3_core
from keystone.contrib.user_crud import core as user_crud_core
from keystone.identity import core as identity_core
from keystone import service


class TestSingularPlural(object):
    def test_keyword_arg_condition_or_methods(self):
        """Raise if we see a keyword arg called 'condition' or 'methods'."""
        modules = [admin_crud_core, s3_core,
                   user_crud_core, identity_core, service]
        for module in modules:
            filename = module.__file__
            if filename.endswith(".pyc"):
                # In Python 2, the .py and .pyc files are in the same dir.
                filename = filename[:-1]
            with open(filename) as fil:
                source = fil.read()
            module = ast.parse(source, filename)
            last_stmt_or_expr = None
            for node in ast.walk(module):
                if isinstance(node, ast.stmt) or isinstance(node, ast.expr):
                    # keyword nodes don't have line numbers, so we need to
                    # get that information from the parent stmt or expr.
                    last_stmt_or_expr = node
                elif isinstance(node, ast.keyword):
                    for bad_word in ["condition", "methods"]:
                        if node.arg == bad_word:
                            raise AssertionError(
                                "Suspicious name '%s' at %s line %s" %
                                (bad_word, filename, last_stmt_or_expr.lineno))
