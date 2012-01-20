#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 OpenStack LLC.
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
#
# Author: Ziad Sawalha (http://launchpad.net/~ziad-sawalha)
# Original maintained at: https://github.com/ziadsawalha/Python-tracer
#

"""
OpenStack Call Tracing Tool

To use this:
1. include the tools directory in your project (__init__.py and tracer.py)
2. import tools.tracer as early as possible into your module
3. add --trace-calls or -t to any argument parsers if you want the argument
to be shown in the usage page

Usage:
Add this as early as possible in the first module called in your service::

    import tools.tracer  # @UnusedImport # module runs on import

If a '-t' or '--trace-calls' parameter is found, it will trace calls to stdout
and space them to show the call graph. Exceptions (errors) will be displayed in
red.

"""

import linecache
import os
import sys


if '--trace-calls' in sys.argv or '-t' in sys.argv:
    # Pop the trace arguments
    for i in range(len(sys.argv)):
        if sys.argv[i] in ['-t', '--trace-calls']:
            sys.argv.pop(i)

    STACK_DEPTH = 0

    # Calculate root project path
    POSSIBLE_TOPDIR = os.path.normpath(os.path.join(
                                       os.path.abspath(sys.argv[0]),
                                       os.pardir,
                                       os.pardir))

    class ConsoleColors():
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'

    def localtrace(frame, event, arg):
        if event == "return":
            global STACK_DEPTH  # pylint: disable=W0603
            STACK_DEPTH = STACK_DEPTH - 1
        elif event == "exception":
            output_exception(frame, arg)
        return None

    def selectivetrace(frame, event, arg):  # pylint: disable=R0911
        global STACK_DEPTH  # pylint: disable=W0603
        if event == "exception":
            output_exception(frame, arg)
        if event == 'call':
            co = frame.f_code
            func_name = co.co_name
            if func_name == 'write':
                # Ignore write() calls from print statements
                return
            func_filename = co.co_filename
            if func_filename == "<string>":
                return
            if func_filename.startswith(("/System", "/Library",
                                         "/usr/lib/py")):
                return
            if 'python' in func_filename:
                return
            if 'macosx' in func_filename:
                return
            output_call(frame, arg)
            global STACK_DEPTH  # pylint: disable=W0603
            STACK_DEPTH = STACK_DEPTH + 1
            return localtrace
        return

    def output_exception(frame, arg):
        exc_type, exc_value, exc_traceback = arg  # pylint: disable=W0612
        if exc_type is StopIteration:
            return
        global STACK_DEPTH  # pylint: disable=W0603
        global POSSIBLE_TOPDIR  # pylint: disable=W0603
        co = frame.f_code
        local_vars = frame.f_locals
        func_name = co.co_name
        line_no = frame.f_lineno
        func_filename = co.co_filename
        func_filename = func_filename.replace(POSSIBLE_TOPDIR, '')
        sys.stdout.write('%s%sERROR: %s %s in %s of %s:%s%s\n'
                              % (ConsoleColors.FAIL, '  ' * STACK_DEPTH,
                                 exc_type.__name__, exc_value, func_name,
                                 func_filename, line_no, ConsoleColors.ENDC))
        filename = co.co_filename
        if filename == "<stdin>":
            filename = "%s.py" % __file__
        if (filename.endswith(".pyc") or
            filename.endswith(".pyo")):
            filename = filename[:-1]
        line = linecache.getline(filename, line_no)
        name = frame.f_globals["__name__"]
        sys.stdout.write('%s%s    %s:%s: %s%s\n' %
                         (ConsoleColors.HEADER, '  ' * STACK_DEPTH, name,
                          line_no, line.rstrip(), ConsoleColors.ENDC))

        sys.stdout.write('%s    locals: %s\n'
                              % ('  ' * STACK_DEPTH,
                                 local_vars))

    def output_call(frame, arg):
        caller = frame.f_back

        if caller:
            global STACK_DEPTH  # pylint: disable=W0603
            global POSSIBLE_TOPDIR  # pylint: disable=W0603
            co = frame.f_code
            func_name = co.co_name
            func_line_no = frame.f_lineno
            func_filename = co.co_filename
            func_filename = func_filename.replace(POSSIBLE_TOPDIR, '')
            caller_line_no = caller.f_lineno
            caller_filename = caller.f_code.co_filename.replace(
                                                        POSSIBLE_TOPDIR, '')
            if caller_filename == func_filename:
                caller_filename = 'line'
            sys.stdout.write('%s%s::%s:%s      (from %s:%s)\n' %
                ('  ' * STACK_DEPTH, func_filename, func_name, func_line_no,
                 caller_filename, caller_line_no))

    sys.stdout.write('Starting OpenStack call tracer\n')
    sys.settrace(selectivetrace)
