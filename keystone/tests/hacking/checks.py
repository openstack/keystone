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
by pycodestyle. The second type is a class that parses AST trees. For more info
please see pycodestyle.py.
"""

import ast
from hacking import core
import re


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
        """Created object automatically by pep8.

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
    """Check for the use of mutable objects as function/method defaults.

    We are only checking for list and dict literals at this time. This means
    that a developer could specify an instance of their own and cause a bug.
    The fix for this is probably more work than it's worth because it will
    get caught during code review.

    """

    name = "check_for_mutable_default_args"
    version = "1.0"

    CHECK_DESC = 'K001 Using mutable as a function/method default'
    MUTABLES = (
        ast.List, ast.ListComp,
        ast.Dict, ast.DictComp,
        ast.Set, ast.SetComp,
        ast.Call)

    def visit_FunctionDef(self, node):
        for arg in node.args.defaults:
            if isinstance(arg, self.MUTABLES):
                self.add_error(arg)

        super(CheckForMutableDefaultArgs, self).generic_visit(node)


@core.flake8ext
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


class CheckForTranslationIssues(BaseASTChecker):

    name = "check_for_translation_issues"
    version = "1.0"
    LOGGING_CHECK_DESC = 'K005 Using translated string in logging'
    USING_DEPRECATED_WARN = 'K009 Using the deprecated Logger.warn'
    LOG_MODULES = ('logging', 'oslo_log.log')
    I18N_MODULES = (
        'keystone.i18n._',
    )
    TRANS_HELPER_MAP = {
        'debug': None,
        'info': '_LI',
        'warning': '_LW',
        'error': '_LE',
        'exception': '_LE',
        'critical': '_LC',
    }

    def __init__(self, tree, filename):
        super(CheckForTranslationIssues, self).__init__(tree, filename)

        self.logger_names = []
        self.logger_module_names = []
        self.i18n_names = {}

        # NOTE(dstanek): this kinda accounts for scopes when talking
        # about only leaf node in the graph
        self.assignments = {}

    def generic_visit(self, node):
        """Called if no explicit visitor function exists for a node."""
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        item._parent = node
                        self.visit(item)
            elif isinstance(value, ast.AST):
                value._parent = node
                self.visit(value)

    def _filter_imports(self, module_name, alias):
        """Keep lists of logging and i18n imports."""
        if module_name in self.LOG_MODULES:
            self.logger_module_names.append(alias.asname or alias.name)
        elif module_name in self.I18N_MODULES:
            self.i18n_names[alias.asname or alias.name] = alias.name

    def visit_Import(self, node):
        for alias in node.names:
            self._filter_imports(alias.name, alias)
        return super(CheckForTranslationIssues, self).generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            full_name = '%s.%s' % (node.module, alias.name)
            self._filter_imports(full_name, alias)
        return super(CheckForTranslationIssues, self).generic_visit(node)

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
        elif isinstance(node, str):
            return node
        else:  # could be Subscript, Call or many more
            return None

    def visit_Assign(self, node):
        """Look for 'LOG = logging.getLogger'.

        This handles the simple case:
          name = [logging_module].getLogger(...)

          - or -

          name = [i18n_name](...)

        And some much more comple ones:
          name = [i18n_name](...) % X

          - or -

          self.name = [i18n_name](...) % X

        """
        attr_node_types = (ast.Name, ast.Attribute)

        if (len(node.targets) != 1
                or not isinstance(node.targets[0], attr_node_types)):
            # say no to: "x, y = ..."
            return super(CheckForTranslationIssues, self).generic_visit(node)

        target_name = self._find_name(node.targets[0])

        if (isinstance(node.value, ast.BinOp) and
                isinstance(node.value.op, ast.Mod)):
            if (isinstance(node.value.left, ast.Call) and
                    isinstance(node.value.left.func, ast.Name) and
                    node.value.left.func.id in self.i18n_names):
                # NOTE(dstanek): this is done to match cases like:
                # `msg = _('something %s') % x`
                node = ast.Assign(value=node.value.left)

        if not isinstance(node.value, ast.Call):
            # node.value must be a call to getLogger
            self.assignments.pop(target_name, None)
            return super(CheckForTranslationIssues, self).generic_visit(node)

        # is this a call to an i18n function?
        if (isinstance(node.value.func, ast.Name)
                and node.value.func.id in self.i18n_names):
            self.assignments[target_name] = node.value.func.id
            return super(CheckForTranslationIssues, self).generic_visit(node)

        if (not isinstance(node.value.func, ast.Attribute)
                or not isinstance(node.value.func.value, attr_node_types)):
            # function must be an attribute on an object like
            # logging.getLogger
            return super(CheckForTranslationIssues, self).generic_visit(node)

        object_name = self._find_name(node.value.func.value)
        func_name = node.value.func.attr

        if (object_name in self.logger_module_names
                and func_name == 'getLogger'):
            self.logger_names.append(target_name)

        return super(CheckForTranslationIssues, self).generic_visit(node)

    def visit_Call(self, node):
        """Look for the 'LOG.*' calls."""
        # obj.method
        if isinstance(node.func, ast.Attribute):
            obj_name = self._find_name(node.func.value)
            if isinstance(node.func.value, ast.Name):
                method_name = node.func.attr
            elif isinstance(node.func.value, ast.Attribute):
                obj_name = self._find_name(node.func.value)
                method_name = node.func.attr
            else:  # could be Subscript, Call or many more
                return (super(CheckForTranslationIssues, self)
                        .generic_visit(node))

            # if dealing with a logger the method can't be "warn"
            if obj_name in self.logger_names and method_name == 'warn':
                msg = node.args[0]  # first arg to a logging method is the msg
                self.add_error(msg, message=self.USING_DEPRECATED_WARN)

            # must be a logger instance and one of the support logging methods
            if (obj_name not in self.logger_names
                    or method_name not in self.TRANS_HELPER_MAP):
                return (super(CheckForTranslationIssues, self)
                        .generic_visit(node))

            # the call must have arguments
            if not node.args:
                return (super(CheckForTranslationIssues, self)
                        .generic_visit(node))

            self._process_log_messages(node)

        return super(CheckForTranslationIssues, self).generic_visit(node)

    def _process_log_messages(self, node):
        msg = node.args[0]  # first arg to a logging method is the msg

        # if first arg is a call to a i18n name
        if (isinstance(msg, ast.Call)
                and isinstance(msg.func, ast.Name)
                and msg.func.id in self.i18n_names):
            self.add_error(msg, message=self.LOGGING_CHECK_DESC)

        # if the first arg is a reference to a i18n call
        elif (isinstance(msg, ast.Name)
                and msg.id in self.assignments):
            self.add_error(msg, message=self.LOGGING_CHECK_DESC)


@core.flake8ext
def dict_constructor_with_sequence_copy(logical_line):
    """Should use a dict comprehension instead of a dict constructor.

    PEP-0274 introduced dict comprehension with performance enhancement
    and it also makes code more readable.

    Okay: lower_res = {k.lower(): v for k, v in res[1].items()}
    Okay: fool = dict(a='a', b='b')
    K008: lower_res = dict((k.lower(), v) for k, v in res[1].items())
    K008:     attrs = dict([(k, _from_json(v))
    K008: dict([[i,i] for i in range(3)])

    """
    MESSAGE = ("K008 Must use a dict comprehension instead of a dict"
               " constructor with a sequence of key-value pairs.")

    dict_constructor_with_sequence_re = (
        re.compile(r".*\bdict\((\[)?(\(|\[)(?!\{)"))

    if dict_constructor_with_sequence_re.match(logical_line):
        yield (0, MESSAGE)
