# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
# Template library copied from bottle: http://bottlepy.org/
#
# Copyright (c) 2011, Marcel Hellkamp.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#


import cgi
import re
import os
import functools
import time
import tokenize
import mimetypes
from webob import Response
from paste.util.template import TemplateError
# from paste.util.datetimeutil import parse_date
import datetime

import keystone.logic.types.fault as fault
from keystone.logic.types.fault import ForbiddenFault

TEMPLATES = {}
DEBUG = False
TEMPLATE_PATH = ['./', './views/']


class BaseTemplate(object):
    """ Base class and minimal API for template adapters """
    extentions = ['tpl', 'html', 'thtml', 'stpl']
    settings = {}  # used in prepare()
    defaults = {}  # used in render()

    def __init__(self, source=None, name=None, lookup=None, encoding='utf8',
                 **settings):
        """ Create a new template.
        If the source parameter (str or buffer) is missing, the name argument
        is used to guess a template filename. Subclasses can assume that
        self.source and/or self.filename are set. Both are strings.
        The lookup, encoding and settings parameters are stored as instance
        variables.
        The lookup parameter stores a list containing directory paths.
        The encoding parameter should be used to decode byte strings or files.
        The settings parameter contains a dict for engine-specific settings.
        """
        lookup = lookup or []

        self.name = name
        self.source = source.read() if hasattr(source, 'read') else source
        self.filename = source.filename \
            if hasattr(source, 'filename') \
            else None
        self.lookup = [os.path.abspath(path) for path in lookup]
        self.encoding = encoding
        self.settings = self.settings.copy()  # Copy from class variable
        self.settings.update(settings)  # Apply
        if not self.source and self.name:
            self.filename = self.search(self.name, self.lookup)
            if not self.filename:
                raise TemplateError('Template %s not found' % repr(name),
                                    (0, 0), None)
        if not self.source and not self.filename:
            raise TemplateError('No template specified', (0, 0), None)
        self.prepare(**self.settings)

    @classmethod
    def search(cls, name, lookup=None):
        """ Search name in all directories specified in lookup.
        First without, then with common extensions. Return first hit. """
        lookup = lookup or []

        if os.path.isfile(name):
            return name
        for spath in lookup:
            fname = os.path.join(spath, name)
            if os.path.isfile(fname):
                return fname
            for ext in cls.extentions:
                if os.path.isfile('%s.%s' % (fname, ext)):
                    return '%s.%s' % (fname, ext)

    @classmethod
    def global_config(cls, key, *args):
        '''This reads or sets the global settings stored in class.settings.'''
        if args:
            cls.settings[key] = args[0]
        else:
            return cls.settings[key]

    def prepare(self, **options):
        """Run preparations (parsing, caching, ...).
        It should be possible to call this again to refresh a template or to
        update settings.
        """
        raise NotImplementedError

    def render(self, **args):
        """Render the template with the specified local variables and return
        a single byte or unicode string. If it is a byte string, the encoding
        must match self.encoding. This method must be thread-safe!
        """
        raise NotImplementedError


class SimpleTemplate(BaseTemplate):
    blocks = ('if', 'elif', 'else', 'try', 'except', 'finally', 'for', 'while',
        'with', 'def', 'class')
    dedent_blocks = ('elif', 'else', 'except', 'finally')
    cache = None
    code = None
    compiled = None
    _str = None
    _escape = None

    def prepare(self, escape_func=cgi.escape, noescape=False):
        self.cache = {}
        if self.source:
            self.code = self.translate(self.source)
            self.compiled = compile(self.code, '<string>', 'exec')
        else:
            self.code = self.translate(open(self.filename).read())
            self.compiled = compile(self.code, self.filename, 'exec')
        enc = self.encoding
        touni = functools.partial(unicode, encoding=self.encoding)
        self._str = lambda x: touni(x, enc)
        self._escape = lambda x: escape_func(touni(x))
        if noescape:
            self._str, self._escape = self._escape, self._str

    def translate(self, template):
        stack = []  # Current Code indentation
        lineno = 0  # Current line of code
        ptrbuffer = []  # Buffer for printable strings and token tuples
        codebuffer = []  # Buffer for generated python code
        functools.partial(unicode, encoding=self.encoding)
        multiline = dedent = False

        def yield_tokens(line):
            for i, part in enumerate(re.split(r'\{\{(.*?)\}\}', line)):
                if i % 2:
                    if part.startswith('!'):
                        yield 'RAW', part[1:]
                    else:
                        yield 'CMD', part
                else:
                    yield 'TXT', part

        def split_comment(codeline):
            """ Removes comments from a line of code. """
            line = codeline.splitlines()[0]
            try:
                tokens = list(tokenize.generate_tokens(iter(line).next))
            except tokenize.TokenError:
                return line.rsplit('#', 1) if '#' in line else (line, '')
            for token in tokens:
                if token[0] == tokenize.COMMENT:
                    start, end = token[2][1], token[3][1]
                    return (
                        codeline[:start] + codeline[end:],
                        codeline[start:end])
            return line, ''

        def flush():
            """Flush the ptrbuffer"""
            if not ptrbuffer:
                return
            cline = ''
            for line in ptrbuffer:
                for token, value in line:
                    if token == 'TXT':
                        cline += repr(value)
                    elif token == 'RAW':
                        cline += '_str(%s)' % value
                    elif token == 'CMD':
                        cline += '_escape(%s)' % value
                    cline += ', '
                cline = cline[:-2] + '\\\n'
            cline = cline[:-2]
            if cline[:-1].endswith('\\\\\\\\\\n'):
                cline = cline[:-7] + cline[-1]  # 'nobr\\\\\n' --> 'nobr'
            cline = '_printlist([' + cline + '])'
            del ptrbuffer[:]  # Do this before calling code() again
            code(cline)

        def code(stmt):
            for line in stmt.splitlines():
                codebuffer.append('  ' * len(stack) + line.strip())

        for line in template.splitlines(True):
            lineno += 1
            line = line if isinstance(line, unicode)\
                        else unicode(line, encoding=self.encoding)
            if lineno <= 2:
                m = re.search(r"%.*coding[:=]\s*([-\w\.]+)", line)
                if m:
                    self.encoding = m.group(1)
                if m:
                    line = line.replace('coding', 'coding (removed)')
            if line.strip()[:2].count('%') == 1:
                line = line.split('%', 1)[1].lstrip()  # Rest of line after %
                cline = split_comment(line)[0].strip()
                cmd = re.split(r'[^a-zA-Z0-9_]', cline)[0]
                flush()  # encodig (TODO: why?)
                if cmd in self.blocks or multiline:
                    cmd = multiline or cmd
                    dedent = cmd in self.dedent_blocks  # "else:"
                    if dedent and not multiline:
                        cmd = stack.pop()
                    code(line)
                    oneline = not cline.endswith(':')  # "if 1: pass"
                    multiline = cmd if cline.endswith('\\') else False
                    if not oneline and not multiline:
                        stack.append(cmd)
                elif cmd == 'end' and stack:
                    code('#end(%s) %s' % (stack.pop(), line.strip()[3:]))
                elif cmd == 'include':
                    p = cline.split(None, 2)[1:]
                    if len(p) == 2:
                        code("_=_include(%s, _stdout, %s)" %
                            (repr(p[0]), p[1]))
                    elif p:
                        code("_=_include(%s, _stdout)" % repr(p[0]))
                    else:  # Empty %include -> reverse of %rebase
                        code("_printlist(_base)")
                elif cmd == 'rebase':
                    p = cline.split(None, 2)[1:]
                    if len(p) == 2:
                        code("globals()['_rebase']=(%s, dict(%s))" % (
                            repr(p[0]), p[1]))
                    elif p:
                        code("globals()['_rebase']=(%s, {})" % repr(p[0]))
                else:
                    code(line)
            else:  # Line starting with text (not '%') or '%%' (escaped)
                if line.strip().startswith('%%'):
                    line = line.replace('%%', '%', 1)
                ptrbuffer.append(yield_tokens(line))
        flush()
        return '\n'.join(codebuffer) + '\n'

    def subtemplate(self, _name, _stdout, **args):
        if _name not in self.cache:
            self.cache[_name] = self.__class__(name=_name, lookup=self.lookup)
        return self.cache[_name].execute(_stdout, **args)

    def execute(self, _stdout, **args):
        env = self.defaults.copy()
        env.update({'_stdout': _stdout, '_printlist': _stdout.extend,
               '_include': self.subtemplate, '_str': self._str,
               '_escape': self._escape})
        env.update(args)
        eval(self.compiled, env)
        if '_rebase' in env:
            subtpl, rargs = env['_rebase']
            subtpl = self.__class__(name=subtpl, lookup=self.lookup)
            rargs['_base'] = _stdout[:]  # copy stdout
            del _stdout[:]  # clear stdout
            return subtpl.execute(_stdout, **rargs)
        return env

    def render(self, **args):
        """ Render the template using keyword arguments as local variables. """
        stdout = []
        self.execute(stdout, **args)
        return ''.join(stdout)


def static_file(resp, req, filename, root, guessmime=True, mimetype=None,
        download=False):
    """ Opens a file in a safe way and returns a HTTPError object with status
        code 200, 305, 401 or 404. Sets Content-Type, Content-Length and
        Last-Modified header. Obeys If-Modified-Since header and HEAD requests.
    """
    root = os.path.abspath(root) + os.sep
    filename = os.path.abspath(os.path.join(root, filename.strip('/\\')))
    if not filename.startswith(root):
        return ForbiddenFault("Access denied.")
    if not os.path.exists(filename) or not os.path.isfile(filename):
        return fault.ItemNotFoundFault("File does not exist.")
    if not os.access(filename, os.R_OK):
        return ForbiddenFault(
            "You do not have permission to access this file.")

    if not mimetype and guessmime:
        resp.content_type = mimetypes.guess_type(filename)[0]
    else:
        resp.content_type = mimetype or 'text/plain'

    if download == True:
        download = os.path.basename(filename)
    if download:
        resp.content_disposition = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    lm = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
        time.gmtime(stats.st_mtime))
    resp.last_modified = lm
    ims = req.environ.get('HTTP_IF_MODIFIED_SINCE')
    if ims:
        ims = ims.split(";")[0].strip()  # IE sends "<date>; length=146"
        try:
            ims = datetime.datetime.fromtimestamp(stats.st_mtime)
            ims = datetime.datetime.ctime(ims)
            filetime = datetime.datetime.fromtimestamp(stats.st_mtime)
            if ims is not None and ims >= filetime:
                resp.date = time.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
                return Response(body=None, status=304,
                                headerlist=resp.headerlist)
        except:
            # TODO(Ziad): handle this better
            pass
    resp.content_length = stats.st_size
    if req.method == 'HEAD':
        return Response(body=None, status=200, headerlist=resp.headerlist)
    else:
        return Response(body=open(filename).read(), status=200,
            headerlist=resp.headerlist)


def template(tpl, template_adapter=SimpleTemplate, **kwargs):
    '''
    Get a rendered template as a string iterator.
    You can use a name, a filename or a template string as first parameter.
    '''
    if tpl not in TEMPLATES or DEBUG:
        settings = kwargs.get('template_settings', {})
        lookup = kwargs.get('template_lookup', TEMPLATE_PATH)
        if isinstance(tpl, template_adapter):
            TEMPLATES[tpl] = tpl
            if settings:
                TEMPLATES[tpl].prepare(**settings)
        elif "\n" in tpl or "{" in tpl or "%" in tpl or '$' in tpl:
            TEMPLATES[tpl] = template_adapter(source=tpl, lookup=lookup,
                **settings)
        else:
            TEMPLATES[tpl] = template_adapter(name=tpl, lookup=lookup,
                **settings)
    return TEMPLATES[tpl].render(**kwargs)
