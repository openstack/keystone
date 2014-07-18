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

"""Keystone's pep8 extensions.

In order to make the review process faster and easier for core devs we are
adding some Keystone specific pep8 checks. This will catch common errors
so that core devs don't have to.

There are two types of pep8 extensions. One is a function that takes either
a physical or logical line. The physical or logical line is the first param
in the function definition and can be followed by other parameters supported
by pep8. The second type is a class that parses AST trees. For more info
please see pep8.py.
"""

import ast

import six


class BaseASTChecker(ast.NodeVisitor):
    """Provides a simple framework for writing AST-based checks.

    Subclasses should implement visit_* methods like any other AST visitor
    implementation. When they detect an error for a particular node the
    method should call ``self.add_error(offending_node)``. Details about
    where in the code the error occurred will be pulled from the node
    object.

    Subclasses should also provide a class variable named CHECK_DESC to
    be used for the human readable error message.

    """

    def __init__(self, tree, filename):
        """This object is created automatically by pep8.

        :param tree: an AST tree
        :param filename: name of the file being analyzed
                         (ignored by our checks)
        """
        self._tree = tree
        self._errors = []

    def run(self):
        """Called automatically by pep8."""
        self.visit(self._tree)
        return self._errors

    def add_error(self, node, message=None):
        """Add an error caused by a node to the list of errors for pep8."""
        message = message or self.CHECK_DESC
        error = (node.lineno, node.col_offset, message, self.__class__)
        self._errors.append(error)


class CheckForMutableDefaultArgs(BaseASTChecker):
    """Checks for the use of mutable objects as function/method defaults.

    We are only checking for list and dict literals at this time. This means
    that a developer could specify an instance of their own and cause a bug.
    The fix for this is probably more work than it's worth because it will
    get caught during code review.

    """

    CHECK_DESC = 'K001 Using mutable as a function/method default'

    # TODO(dstanek): once we drop support for Python 2.6 we can add ast.Set,
    # ast.DictComp and ast.SetComp to MUTABLES. Don't forget the tests!
    MUTABLES = (ast.List, ast.ListComp, ast.Dict)

    def visit_FunctionDef(self, node):
        for arg in node.args.defaults:
            if isinstance(arg, self.MUTABLES):
                self.add_error(arg)

        super(CheckForMutableDefaultArgs, self).generic_visit(node)


def block_comments_begin_with_a_space(physical_line, line_number):
    """There should be a space after the # of block comments.

    There is already a check in pep8 that enforces this rule for
    inline comments.

    Okay: # this is a comment
    Okay: #!/usr/bin/python
    Okay: #  this is a comment
    K002: #this is a comment

    """
    MESSAGE = "K002 block comments should start with '# '"

    # shebangs are OK
    if line_number == 1 and physical_line.startswith('#!'):
        return

    text = physical_line.strip()
    if text.startswith('#'):  # look for block comments
        if len(text) > 1 and not text[1].isspace():
            return physical_line.index('#'), MESSAGE


class CheckForAssertingNoneEquality(BaseASTChecker):
    """Ensures that code does not use a None with assert(Not*)Equal."""

    CHECK_DESC_IS = ('K003 Use self.assertIsNone(...) when comparing '
                     'against None')
    CHECK_DESC_ISNOT = ('K004 Use assertIsNotNone(...) when comparing '
                        ' against None')

    def visit_Call(self, node):
        # NOTE(dstanek): I wrote this in a verbose way to make it easier to
        # read for those that have little experience with Python's AST.

        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'assertEqual':
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == 'None':
                        self.add_error(node, message=self.CHECK_DESC_IS)
            elif node.func.attr == 'assertNotEqual':
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == 'None':
                        self.add_error(node, message=self.CHECK_DESC_ISNOT)

        super(CheckForAssertingNoneEquality, self).generic_visit(node)


class CheckForTranslationsInDebugLogging(BaseASTChecker):

    CHECK_DESC = 'K005 Using translated string in debug logging'
    LOG_MODULES = ('logging', 'keystone.openstack.common.log')
    I18N_MODULES = ('keystone.i18n._')

    def __init__(self, tree, filename):
        super(CheckForTranslationsInDebugLogging, self).__init__(
            tree, filename)

        self.logger_names = []
        self.logger_module_names = []
        self.i18n_names = []

        # NOTE(dstanek): this kinda accounts for scopes when talking
        # about only leaf node in the graph
        self.assignments = []

    def _filter_imports(self, module_name, alias):
        """Keeps lists of logging and i18n imports

        """
        if module_name in self.LOG_MODULES:
            self.logger_module_names.append(alias.asname or alias.name)
        elif module_name in self.I18N_MODULES:
            self.i18n_names.append(alias.asname or alias.name)

    def visit_Import(self, node):
        for alias in node.names:
            self._filter_imports(alias.name, alias)
        super(CheckForTranslationsInDebugLogging, self).generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            full_name = '%s.%s' % (node.module, alias.name)
            self._filter_imports(full_name, alias)
        super(CheckForTranslationsInDebugLogging, self).generic_visit(node)

    def _find_name(self, node):
        """Return the fully qualified name or a Name or Attribute."""
        if isinstance(node, ast.Name):
            return node.id
        elif (isinstance(node, ast.Attribute)
                and isinstance(node.value, (ast.Name, ast.Attribute))):
            method_name = node.attr
            obj_name = self._find_name(node.value)
            if obj_name is None:
                return None
            return obj_name + '.' + method_name
        elif isinstance(node, six.string_types):
            return node
        else:  # could be Subscript, Call or many more
            return None

    def visit_Assign(self, node):
        """Look for 'LOG = logging.getLogger'

        This only handles the simple case:
          name = [logging_module].getLogger(...)

          - or -

          name = [i18n_name](...)

        """
        attr_node_types = (ast.Name, ast.Attribute)

        if (len(node.targets) != 1
                or not isinstance(node.targets[0], attr_node_types)):
            # say no to: "x, y = ..."
            return

        target_name = self._find_name(node.targets[0])

        if not isinstance(node.value, ast.Call):
            # node.value must be a call to getLogger
            return

        # is this a call to an i18n function?
        if (isinstance(node.value.func, ast.Name)
                and node.value.func.id in self.i18n_names):
            self.assignments.append(target_name)
            return

        if (not isinstance(node.value.func, ast.Attribute)
                or not isinstance(node.value.func.value, attr_node_types)):
            # function must be an attribute on an object like
            # logging.getLogger
            return

        object_name = self._find_name(node.value.func.value)
        func_name = node.value.func.attr

        if (object_name in self.logger_module_names
                and func_name == 'getLogger'):
            self.logger_names.append(target_name)

    def visit_Call(self, node):
        """Look for the 'LOG.debug' calls.

        """

        # obj.method
        if isinstance(node.func, ast.Attribute):
            obj_name = self._find_name(node.func.value)
            if isinstance(node.func.value, ast.Name):
                method_name = node.func.attr
            elif isinstance(node.func.value, ast.Attribute):
                obj_name = self._find_name(node.func.value)
                method_name = node.func.attr
            else:  # could be Subscript, Call or many more
                return

            # must be a logger instance and the debug method
            if obj_name not in self.logger_names or method_name != 'debug':
                return

            # the call must have arguments
            if not len(node.args):
                return

            # if first arg is a call to a i18n name
            if (isinstance(node.args[0], ast.Call)
                    and isinstance(node.args[0].func, ast.Name)
                    and node.args[0].func.id in self.i18n_names):
                self.add_error(node.args[0])

            # if the first arg is a reference to a i18n call
            elif (isinstance(node.args[0], ast.Name)
                    and node.args[0].id in self.assignments):
                self.add_error(node.args[0])


def factory(register):
    register(CheckForMutableDefaultArgs)
    register(block_comments_begin_with_a_space)
    register(CheckForAssertingNoneEquality)
    register(CheckForTranslationsInDebugLogging)
