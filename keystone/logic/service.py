# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
from datetime import timedelta

import keystone.logic.types.auth as auth
import keystone.logic.types.tenant as tenants
import keystone.logic.types.atom as atom
import keystone.logic.types.fault as fault
import keystone.logic.types.user as users

import keystone.db.sqlalchemy.api as db_api
import keystone.db.sqlalchemy.models as db_models

import uuid
import cgi
import re
import os
import functools
import time
TEMPLATES = {}
DEBUG = False
TEMPLATE_PATH = ['./', './views/']


##""" this part of below code is used from bottle.py """
class BaseTemplate(object):
    """ Base class and minimal API for template adapters """
    extentions = ['tpl','html','thtml','stpl']
    settings = {} #used in prepare()
    defaults = {} #used in render()

    def __init__(self, source=None, name=None, lookup=[], encoding='utf8', **settings):
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
        self.name = name
        self.source = source.read() if hasattr(source, 'read') else source
        self.filename = source.filename if hasattr(source, 'filename') else None
        self.lookup = map(os.path.abspath, lookup)
        self.encoding = encoding
        self.settings = self.settings.copy() # Copy from class variable
        self.settings.update(settings) # Apply 
        if not self.source and self.name:
            self.filename = self.search(self.name, self.lookup)
            if not self.filename:
                raise TemplateError('Template %s not found.' % repr(name))
        if not self.source and not self.filename:
            raise TemplateError('No template specified.')
        self.prepare(**self.settings)

    @classmethod
    def search(cls, name, lookup=[]):
        """ Search name in all directories specified in lookup.
        First without, then with common extensions. Return first hit. """
        if os.path.isfile(name): return name
        for spath in lookup:
            fname = os.path.join(spath, name)
            if os.path.isfile(fname):
                return fname
            for ext in cls.extentions:
                if os.path.isfile('%s.%s' % (fname, ext)):
                    return '%s.%s' % (fname, ext)

    @classmethod
    def global_config(cls, key, *args):
        ''' This reads or sets the global settings stored in class.settings. '''
        if args:
            cls.settings[key] = args[0]
        else:
            return cls.settings[key]

    def prepare(self, **options):
        """ Run preparations (parsing, caching, ...).
        It should be possible to call this again to refresh a template or to
        update settings.
        """
        raise NotImplementedError

    def render(self, **args):
        """ Render the template with the specified local variables and return
        a single byte or unicode string. If it is a byte string, the encoding
        must match self.encoding. This method must be thread-safe!
        """
        raise NotImplementedError


class SimpleTemplate(BaseTemplate):
    blocks = ('if','elif','else','try','except','finally','for','while','with','def','class')
    dedent_blocks = ('elif', 'else', 'except', 'finally')

    def prepare(self, escape_func=cgi.escape, noescape=False):
        self.cache = {}
        if self.source:
            self.code = self.translate(self.source)
            self.co = compile(self.code, '<string>', 'exec')
        else:
            self.code = self.translate(open(self.filename).read())
            self.co = compile(self.code, self.filename, 'exec')
        enc = self.encoding
        touni = functools.partial(unicode, encoding=self.encoding)
        self._str = lambda x: touni(x, enc)
        self._escape = lambda x: escape_func(touni(x))
        if noescape:
            self._str, self._escape = self._escape, self._str

    def translate(self, template):
        stack = [] # Current Code indentation
        lineno = 0 # Current line of code
        ptrbuffer = [] # Buffer for printable strings and token tuple instances
        codebuffer = [] # Buffer for generated python code
        touni = functools.partial(unicode, encoding=self.encoding)
        multiline = dedent = False

        def yield_tokens(line):
            for i, part in enumerate(re.split(r'\{\{(.*?)\}\}', line)):
                if i % 2:
                    if part.startswith('!'): yield 'RAW', part[1:]
                    else: yield 'CMD', part
                else: yield 'TXT', part

        def split_comment(codeline):
            """ Removes comments from a line of code. """
            line = codeline.splitlines()[0]
            try:
                tokens = list(tokenize.generate_tokens(iter(line).next))
            except tokenize.TokenError:
                return line.rsplit('#',1) if '#' in line else (line, '')
            for token in tokens:
                if token[0] == tokenize.COMMENT:
                    start, end = token[2][1], token[3][1]
                    return codeline[:start] + codeline[end:], codeline[start:end]
            return line, ''

        def flush(): # Flush the ptrbuffer
            if not ptrbuffer: return
            cline = ''
            for line in ptrbuffer:
                for token, value in line:
                    if token == 'TXT': cline += repr(value)
                    elif token == 'RAW': cline += '_str(%s)' % value
                    elif token == 'CMD': cline += '_escape(%s)' % value
                    cline +=  ', '
                cline = cline[:-2] + '\\\n'
            cline = cline[:-2]
            if cline[:-1].endswith('\\\\\\\\\\n'):
                cline = cline[:-7] + cline[-1] # 'nobr\\\\\n' --> 'nobr'
            cline = '_printlist([' + cline + '])'
            del ptrbuffer[:] # Do this before calling code() again
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
                if m: self.encoding = m.group(1)
                if m: line = line.replace('coding','coding (removed)')
            if line.strip()[:2].count('%') == 1:
                line = line.split('%',1)[1].lstrip() # Full line following the %
                cline = split_comment(line)[0].strip()
                cmd = re.split(r'[^a-zA-Z0-9_]', cline)[0]
                flush() ##encodig (TODO: why?)
                if cmd in self.blocks or multiline:
                    cmd = multiline or cmd
                    dedent = cmd in self.dedent_blocks # "else:"
                    if dedent and not oneline and not multiline:
                        cmd = stack.pop()
                    code(line)
                    oneline = not cline.endswith(':') # "if 1: pass"
                    multiline = cmd if cline.endswith('\\') else False
                    if not oneline and not multiline:
                        stack.append(cmd)
                elif cmd == 'end' and stack:
                    code('#end(%s) %s' % (stack.pop(), line.strip()[3:]))
                elif cmd == 'include':
                    p = cline.split(None, 2)[1:]
                    if len(p) == 2:
                        code("_=_include(%s, _stdout, %s)" % (repr(p[0]), p[1]))
                    elif p:
                        code("_=_include(%s, _stdout)" % repr(p[0]))
                    else: # Empty %include -> reverse of %rebase
                        code("_printlist(_base)")
                elif cmd == 'rebase':
                    p = cline.split(None, 2)[1:]
                    if len(p) == 2:
                        code("globals()['_rebase']=(%s, dict(%s))" % (repr(p[0]), p[1]))
                    elif p:
                        code("globals()['_rebase']=(%s, {})" % repr(p[0]))
                else:
                    code(line)
            else: # Line starting with text (not '%') or '%%' (escaped)
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
        eval(self.co, env)
        if '_rebase' in env:
            subtpl, rargs = env['_rebase']
            subtpl = self.__class__(name=subtpl, lookup=self.lookup)
            rargs['_base'] = _stdout[:] #copy stdout
            del _stdout[:] # clear stdout
            return subtpl.execute(_stdout, **rargs)
        return env

    def render(self, **args):
        """ Render the template using keyword arguments as local variables. """
        stdout = []
        self.execute(stdout, **args)
        return ''.join(stdout)

def static_file(resp, req, filename, root, guessmime=True, mimetype=None, download=False):
    """ Opens a file in a safe way and returns a HTTPError object with status
        code 200, 305, 401 or 404. Sets Content-Type, Content-Length and
        Last-Modified header. Obeys If-Modified-Since header and HEAD requests.
    """
    root = os.path.abspath(root) + os.sep
    filename = os.path.abspath(os.path.join(root, filename.strip('/\\')))
    header = dict()
    if not filename.startswith(root):
        #return HTTPError(403, "Access denied.")
        return ForbiddenFault("Access denied.")
    if not os.path.exists(filename) or not os.path.isfile(filename):
        #return HTTPError(404, "File does not exist.")
        return fault.ItemNotFoundFault("File does not exist.")
    if not os.access(filename, os.R_OK):
        #return HTTPError(403, "You do not have permission to access this file.")
        return ForbiddenFault("You do not have permission to access this file.")

    if not mimetype and guessmime:
        resp.headers['Content-Type'] = mimetypes.guess_type(filename)[0]
    else:
        resp.headers['Content-Type'] = mimetype if mimetype else 'text/plain'

    if download == True:
        download = os.path.basename(filename)
    if download:
        resp.headers['Content-Disposition'] = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    lm = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(stats.st_mtime))
    resp.headers['Last-Modified'] = lm
    ims = req.environ.get('HTTP_IF_MODIFIED_SINCE')
    if ims:
        ims = ims.split(";")[0].strip() # IE sends "<date>; length=146"
        ims = parse_date(ims)
        if ims is not None and ims >= int(stats.st_mtime):
            resp.headers['Date'] = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
            return Response(status=304, header=header)
    resp.headers['Content-Length'] = stats.st_size
    if req.method == 'HEAD':
        return resp('', header=header)
    else:
        return resp(open(filename, 'rb'), header=header)


def template(tpl, template_adapter=SimpleTemplate, **kwargs):
    '''
    Get a rendered template as a string iterator.
    You can use a name, a filename or a template string as first parameter.
    '''
    if tpl not in TEMPLATES or DEBUG:
        settings = kwargs.get('template_settings',{})
        lookup = kwargs.get('template_lookup', TEMPLATE_PATH)
        if isinstance(tpl, template_adapter):
            TEMPLATES[tpl] = tpl
            if settings: TEMPLATES[tpl].prepare(**settings)
        elif "\n" in tpl or "{" in tpl or "%" in tpl or '$' in tpl:
            TEMPLATES[tpl] = template_adapter(source=tpl, lookup=lookup, **settings)
        else:
            TEMPLATES[tpl] = template_adapter(name=tpl, lookup=lookup, **settings)
    if not TEMPLATES[tpl]:
        abort(500, 'Template (%s) not found' % tpl)
    return TEMPLATES[tpl].render(**kwargs)


##""" this part of above code is used from bottle.py """


class IDMService(object):
    "This is the logical implemenation of the IDM service"

    #
    #  Token Operations
    #
    def authenticate(self, credentials):
        if not isinstance(credentials, auth.PasswordCredentials):
            raise fault.BadRequestFault("Expecting Password Credentials!")

        duser = db_api.user_get(credentials.username)
        if duser == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not duser.enabled:
            raise fault.UserDisabledFault("Your account has been disabled")
        if duser.password != credentials.password:
            raise fault.UnauthorizedFault("Unauthorized")

        #
        # Look for an existing token, or create one,
        # TODO: Handle tenant/token search
        #
        dtoken = db_api.token_for_user(duser.id)
        if not dtoken or dtoken.expires < datetime.now():
            dtoken = db_models.Token()
            dtoken.token_id = str(uuid.uuid4())
            dtoken.user_id = duser.id
            if not duser.tenants:
                raise fault.IDMFault("Strange: user %s is not associated "
                                     "with a tenant!" % duser.id)
            dtoken.tenant_id = duser.tenants[0].tenant_id
            dtoken.expires = datetime.now() + timedelta(days=1)

            db_api.token_create(dtoken)

        return self.__get_auth_data(dtoken, duser)

    def validate_token(self, admin_token, token_id, belongs_to=None):
        self.__validate_token(admin_token)

        (dtoken, duser) = self.__get_dauth_data(token_id)

        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        if dtoken.expires < datetime.now():
            raise fault.ItemNotFoundFault("Token not found")

        if belongs_to != None and dtoken.tenant_id != belongs_to:
            raise fault.ItemNotFoundFault("Token not found")

        return self.__get_auth_data(dtoken, duser)

    def revoke_token(self, admin_token, token_id):
        self.__validate_token(admin_token)

        dtoken = db_api.token_get(token_id)
        if not dtoken:
            raise fault.ItemNotFoundFault("Token not found")

        db_api.token_delete(token_id)

    #
    #   Tenant Operations
    #
    def create_tenant(self, admin_token, tenant):
        self.__validate_token(admin_token)

        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")

        if tenant.tenant_id == None:
            raise fault.BadRequestFault("Expecting a unique Tenant Id")

        if db_api.tenant_get(tenant.tenant_id) != None:
            raise fault.TenantConflictFault(
                "A tenant with that id already exists")

        dtenant = db_models.Tenant()
        dtenant.id = tenant.tenant_id
        dtenant.desc = tenant.description
        dtenant.enabled = tenant.enabled

        db_api.tenant_create(dtenant)

        return tenant

    #def get_tenants(self, admin_token, marker, limit):
    #    self.__validate_token(admin_token)
    #
    #    ts = []
    #   dtenants = db_api.tenant_get_all()
    #   for dtenant in dtenants:
    #       ts.append(tenants.Tenant(dtenant.id,
    #                                dtenant.desc, dtenant.enabled))

    #    return tenants.Tenants(ts, [])


    ##
    ##    GET Tenants with Pagination
    ##

    def get_tenants(self, admin_token, marker, limit, url):
        self.__validate_token(admin_token)

        ts = []
        dtenants = db_api.tenant_get_page(marker,limit)
        for dtenant in dtenants:
            ts.append(tenants.Tenant(dtenant.id,
                                     dtenant.desc, dtenant.enabled))
        prev,next=db_api.tenant_get_page_markers(marker,limit)
        links=[]
        if prev:
            links.append(atom.Link('prev',"%s?'marker=%s&limit=%s'" % (url,prev,limit)))
        if next:
            links.append(atom.Link('next',"%s?'marker=%s&limit=%s'" % (url,next,limit)))


        return tenants.Tenants(ts, links)


    def get_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant could not be found")

        return tenants.Tenant(dtenant.id, dtenant.desc, dtenant.enabled)

    def update_tenant(self, admin_token, tenant_id, tenant):
        self.__validate_token(admin_token)

        if not isinstance(tenant, tenants.Tenant):
            raise fault.BadRequestFault("Expecting a Tenant")
        True

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant cloud not be found")

        values = {'desc': tenant.description, 'enabled': tenant.enabled}

        db_api.tenant_update(tenant_id, values)

        return tenants.Tenant(dtenant.id, tenant.description, tenant.enabled)

    def delete_tenant(self, admin_token, tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant cloud not be found")

        if not db_api.tenant_is_empty(tenant_id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains users or groups")

        db_api.tenant_delete(dtenant.id)
        return None

    #
    #   Tenant Group Operations
    #

    def create_tenant_group(self, admin_token, tenant, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")

        if tenant == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        dtenant = db_api.tenant_get(tenant)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")


        if group.group_id == None:
            raise fault.BadRequestFault("Expecting a Group Id")

        if db_api.group_get(group.group_id) != None:
            raise fault.TenantGroupConflictFault(
                "A tenant group with that id already exists")

        dtenant = db_models.Group()
        dtenant.id = group.group_id
        dtenant.desc = group.description
        dtenant.tenant_id = tenant

        db_api.tenant_group_create(dtenant)

        return tenants.Group(dtenant.id, dtenant.desc, dtenant.tenant_id)



    def get_tenant_groups(self, admin_token, tenantId, marker, limit, url):
        self.__validate_token(admin_token)
        if tenantId == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        dtenant = db_api.tenant_get(tenantId)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []
        dtenantgroups = db_api.tenant_group_get_page(tenantId, marker,limit)

        for dtenantgroup in dtenantgroups:
            ts.append(tenants.Group(dtenantgroup.id,
                                     dtenantgroup.desc, dtenantgroup.tenant_id))
        prev,next=db_api.tenant_group_get_page_markers(tenantId, marker, limit)
        links=[]
        if prev:
            links.append(atom.Link('prev',"%s?'marker=%s&limit=%s'" % (url,prev,limit)))
        if next:
            links.append(atom.Link('next',"%s?'marker=%s&limit=%s'" % (url,next,limit)))


        return tenants.Groups(ts, links)

    def get_tenant_group(self, admin_token, tenant_id, group_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group_get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")


        return tenants.Group(dtenant.id, dtenant.desc, dtenant.tenant_id)


    def update_tenant_group(self, admin_token, tenant_id, group_id, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")
        True

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group_get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")

        if group_id != group.group_id:
                raise fault.BadRequestFault("Wrong Data Provided,Group id not matching")

        if str(tenant_id) != str(group.tenant_id):
                raise fault.BadRequestFault("Wrong Data Provided, Tenant id not matching ")

        values = {'desc': group.description}

        db_api.tenant_group_update(group_id, tenant_id, values)

        return tenants.Group(group_id, group.description, tenant_id)


    def delete_tenant_group(self, admin_token, tenant_id, group_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)

        if dtenant == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        dtenant = db_api.tenant_group_get(group_id, tenant_id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The tenant group not found")

        if not db_api.tenant_group_is_empty(group_id):
            raise fault.ForbiddenFault("You may not delete a tenant that "
                                       "contains users or groups")

        db_api.tenant_group_delete(group_id, tenant_id)
        return None


    def get_users_tenant_group(self, admin_token, tenantId, groupId, marker,
                               limit, url):
        self.__validate_token(admin_token)
        if tenantId == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")
        
        if db_api.tenant_get(tenantId) == None:
            raise fault.ItemNotFoundFault("The tenant not found")
        
        if db_api.tenant_group_get(groupId, tenantId) == None:
            raise fault.ItemNotFoundFault(
                "A tenant group with that id not found")
        ts = []
        dgroupusers = db_api.users_tenant_group_get_page(groupId, marker, 
                                                          limit)
        for dgroupuser, dgroupuserAsso in dgroupusers:
            
            ts.append(tenants.User(dgroupuser.id,
                                   dgroupuser.email, dgroupuser.enabled, 
                                   tenantId, None))
        links = []
        if ts.__len__():
            prev, next = db_api.users_tenant_group_get_page_markers(groupId,
                                                             marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" % 
                                      (url, prev, limit)))
            if next:             
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" % 
                                      (url, next, limit)))
        return tenants.Users(ts, links)
    
    def add_user_tenant_group(self, admin_token, tenant, group, user):
        self.__validate_token(admin_token)
        
        if db_api.tenant_get(tenant) == None:
            raise fault.ItemNotFoundFault("The Tenant not found")
        
        if db_api.group_get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user_get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")
        
        if db_api.tenant_group_get(group, tenant) == None:
            raise fault.ItemNotFoundFault("A tenant group with"
                                           " that id not found")
        
        if db_api.user_get_by_group(user, group) != None:
            raise fault.UserGroupConflictFault(
                "A user with that id already exists in group")
        
        dusergroup = db_models.UserGroupAssociation()
        dusergroup.user_id = user
        dusergroup.group_id = group
        db_api.user_tenant_group(dusergroup)
        
        return tenants.User(duser.id, duser.email, duser.enabled, 
                            tenant, group)
    
    def delete_user_tenant_group(self, admin_token, tenant, group, user):
        self.__validate_token(admin_token)
        
        if db_api.tenant_get(tenant) == None:
            raise fault.ItemNotFoundFault("The Tenant not found")
        
        if db_api.group_get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user_get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")
        
        if db_api.tenant_group_get(group, tenant) == None:
            raise fault.ItemNotFoundFault("A tenant group with"
                                          " that id not found")
        
        if db_api.user_get_by_group(user, group) == None:
            raise fault.ItemNotFoundFault("A user with that id "
                                          "in a group not found")
        
        db_api.user_tenant_group_delete(user, group)
        return None


    #
    # Private Operations
    #
    def __get_dauth_data(self, token_id):
        """return token and user object for a token_id"""

        token = None
        user = None
        if token_id:
            token = db_api.token_get(token_id)
            if token:
                user = db_api.user_get(token.user_id)
        return (token, user)

    #
    #   User Operations
    #
    def create_user(self, admin_token, tenant_id, user):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        if not isinstance(user, users.User):
            raise fault.BadRequestFault("Expecting a User")

        if user.user_id == None:
            raise fault.BadRequestFault("Expecting a unique User Id")

        if db_api.user_get(user.user_id) != None:
            raise fault.UserConflictFault(
                "An user with that id already exists")

        if db_api.user_get_email(user.email) != None:
            raise fault.EmailConflictFault(
                "Email already exists")


        duser_tenant=db_models.UserTenantAssociation()
        duser_tenant.user_id=user.user_id
        duser_tenant.tenant_id=tenant_id
        db_api.user_tenant_create(duser_tenant)

        duser = db_models.User()
        duser.id = user.user_id
        duser.password = user.password
        duser.email = user.email
        duser.enabled = user.enabled
        db_api.user_create(duser)

        return user

    def get_tenant_users(self, admin_token, tenant_id, marker, limit,url):
        self.__validate_token(admin_token)

        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if db_api.tenant_get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")
        ts = []
        dtenantusers = db_api.users_get_by_tenant_get_page(tenant_id, marker,
                                                          limit)
        for dtenantuser, dtenantuserAsso in dtenantusers:
            ts.append(users.User(None,dtenantuser.id,tenant_id,
                                   dtenantuser.email, dtenantuser.enabled))
        links = []
        if ts.__len__():
            prev, next =db_api.users_get_by_tenant_get_page_markers(tenant_id,
                                                             marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return users.Users(ts, links)

    def get_user(self, admin_token, tenant_id, user_id):
        self.__validate_token(admin_token)
        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        duser = db_api.user_get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")

        if len(duser.tenants) > 0:
            tenant_user = duser.tenants[0].tenant_id
        else:
            tenant_user = tenant_id

        ts = []
        dusergroups = db_api.user_groups_get_all(user_id)

        for dusergroup, dusergroupAsso in dusergroups:


            ts.append(tenants.Group(dusergroup.id,dusergroup.tenant_id,None))

        return users.User_Update(None,duser.id, tenant_user, duser.email, \
                          duser.enabled,ts )

    def update_user(self, admin_token, user_id, user,tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        duser = db_api.user_get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")


        if not isinstance(user, users.User):
            raise fault.BadRequestFault("Expecting a User")
        True
        duser = db_api.user_get_update(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")
        if db_api.user_get_email(user.email) != None:
            raise fault.EmailConflictFault(
                "Email already exists")

        values = {'email': user.email}

        db_api.user_update(user_id, values)
        duser = db_api.user_get_update(user_id)
        return users.User(duser.password, duser.id, tenant_id, duser.email, \
                          duser.enabled)

    def set_user_password(self, admin_token, user_id, user,tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        duser = db_api.user_get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")


        if not isinstance(user, users.User):
            raise fault.BadRequestFault("Expecting a User")
        True
        duser = db_api.user_get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'password': user.password}

        db_api.user_update(user_id, values)

        return users.User(user.password, '', '', '', '')

    def enable_disable_user(self, admin_token, user_id, user,tenant_id):
        self.__validate_token(admin_token)

        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        duser = db_api.user_get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")

        if not duser.enabled:
            raise fault.UserDisabledFault("User has been disabled")


        if not isinstance(user, users.User):
            raise fault.BadRequestFault("Expecting a User")
        True
        duser = db_api.user_get(user_id)
        if duser == None:
            raise fault.ItemNotFoundFault("The user could not be found")

        values = {'enabled': user.enabled}

        db_api.user_update(user_id, values)

        return users.User('','','','',user.enabled)

    def delete_user(self, admin_token, user_id, tenant_id):
        self.__validate_token(admin_token)
        dtenant = db_api.tenant_get(tenant_id)
        if dtenant == None:
            raise fault.UnauthorizedFault("Unauthorized")
        if not dtenant.enabled:
            raise fault.TenantDisabledFault("Your account has been disabled")

        duser = db_api.user_get(user_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be found")
        duser = db_api.user_get_by_tenant(user_id, tenant_id)
        if not duser:
            raise fault.ItemNotFoundFault("The user could not be "
                                        "found under given tenant")

        db_api.user_delete_tenant(user_id, tenant_id)
        return None

    def get_user_groups(self, admin_token, tenant_id,user_id, marker, limit, url):
        self.__validate_token(admin_token)

        if tenant_id == None:
            raise fault.BadRequestFault("Expecting a Tenant Id")

        if db_api.tenant_get(tenant_id) == None:
            raise fault.ItemNotFoundFault("The tenant not found")

        ts = []
        dusergroups = db_api.groups_get_by_user_get_page(user_id, marker,
                                                          limit)
        print dusergroups
        for dusergroup, dusergroupAsso in dusergroups:


            ts.append(tenants.Group(dusergroup.id,dusergroup.desc,dusergroup.tenant_id))
        links = []
        if ts.__len__():
            prev, next =db_api.groups_get_by_user_get_page_markers(user_id, marker,
                                                          limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                      (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                      (url, next, limit)))
        return tenants.Groups(ts, links)

    #

    #
    #   Global Group Operations
    #

    def __check_create_global_tenant(self):

        dtenant = db_api.tenant_get('GlobalTenant')

        if dtenant is None:
            dtenant = db_models.Tenant()
            dtenant.id = 'GlobalTenant'
            dtenant.desc = 'GlobalTenant is Default tenant for global groups'
            dtenant.enabled = True
            db_api.tenant_create(dtenant)
        return dtenant

    def create_global_group(self, admin_token, group):
        self.__validate_token(admin_token)

        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")

        if group.group_id == None:
            raise fault.BadRequestFault("Expecting a Group Id")

        if db_api.group_get(group.group_id) != None:
            raise fault.TenantGroupConflictFault(
                "A tenant group with that id already exists")
        gtenant = self.__check_create_global_tenant()
        dtenant = db_models.Group()
        dtenant.id = group.group_id
        dtenant.desc = group.description
        dtenant.tenant_id = gtenant.id
        db_api.tenant_group_create(dtenant)
        return tenants.Group(dtenant.id, dtenant.desc, None)

    def get_global_groups(self, admin_token,  marker, limit, url):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        ts = []
        dtenantgroups = db_api.tenant_group_get_page(gtenant.id, \
                                                      marker, limit)

        for dtenantgroup in dtenantgroups:
            ts.append(tenants.Group(dtenantgroup.id,
                                     dtenantgroup.desc))
        prev, next = db_api.tenant_group_get_page_markers(gtenant.id,
                                                       marker, limit)
        links = []
        if prev:
            links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'" %
                                  (url, prev, limit)))
        if next:
            links.append(atom.Link('next', "%s?'marker=%s&limit=%s'" %
                                  (url, next, limit)))
        return tenants.Groups(ts, links)

    def get_global_group(self, admin_token, group_id):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        dtenant = db_api.tenant_get(gtenant.id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The Global tenant not found")

        dtenant = db_api.tenant_group_get(group_id, gtenant.id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The Global tenant group not found")
        return tenants.Group(dtenant.id, dtenant.desc)

    def update_global_group(self, admin_token, group_id, group):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        if not isinstance(group, tenants.Group):
            raise fault.BadRequestFault("Expecting a Group")

        dtenant = db_api.tenant_get(gtenant.id)
        if dtenant == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        dtenant = db_api.tenant_group_get(group_id, gtenant.id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The Global tenant group not found")
        if group_id != group.group_id:
                raise fault.BadRequestFault("Wrong Data Provided,"
                                            "Group id not matching")

        values = {'desc': group.description}
        db_api.tenant_group_update(group_id, gtenant.id, values)
        return tenants.Group(group_id, group.description, gtenant.id)

    def delete_global_group(self, admin_token, group_id):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        dtenant = db_api.tenant_get(gtenant.id)

        if dtenant == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        dtenant = db_api.tenant_group_get(group_id, gtenant.id)
        if not dtenant:
            raise fault.ItemNotFoundFault("The global tenant group not found")

        if not db_api.tenant_group_is_empty(group_id):
            raise fault.ForbiddenFault("You may not delete a group that "
                                       "contains users")

        db_api.tenant_group_delete(group_id, gtenant.id)
        return None

    def get_users_global_group(self, admin_token, groupId, marker, limit, url):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()
        if gtenant.id == None:
            raise fault.BadRequestFault("Expecting a global Tenant")

        if db_api.tenant_get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The global tenant not found")

        if db_api.tenant_group_get(groupId, gtenant.id) == None:
            raise fault.ItemNotFoundFault(
                "A global tenant group with that id not found")
        ts = []
        dgroupusers = db_api.users_tenant_group_get_page(groupId, marker,
                                                         limit)
        for dgroupuser, dgroupuserassoc in dgroupusers:
            ts.append(tenants.User(dgroupuser.id, dgroupuser.email,
                                   dgroupuser.enabled))
        links = []
        if ts.__len__():
            prev, next = db_api.users_tenant_group_get_page_markers(groupId,
                                                                marker, limit)
            if prev:
                links.append(atom.Link('prev', "%s?'marker=%s&limit=%s'"
                                       % (url, prev, limit)))
            if next:
                links.append(atom.Link('next', "%s?'marker=%s&limit=%s'"
                                       % (url, next, limit)))
        return tenants.Users(ts, links)

    def add_user_global_group(self, admin_token, group, user):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()

        if db_api.tenant_get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The Global Tenant not found")

        if db_api.group_get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user_get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group_get(group, gtenant.id) == None:
            raise fault.ItemNotFoundFault("A global tenant group with"
                                          " that id not found")

        if db_api.user_get_by_group(user, group) != None:
            raise fault.UserGroupConflictFault(
                "A user with that id already exists in group")

        dusergroup = db_models.UserGroupAssociation()
        dusergroup.user_id = user
        dusergroup.group_id = group
        db_api.user_tenant_group(dusergroup)

        return tenants.User(duser.id, duser.email, duser.enabled,
                           group_id = group)

    def delete_user_global_group(self, admin_token, group, user):
        self.__validate_token(admin_token)
        gtenant = self.__check_create_global_tenant()

        if db_api.tenant_get(gtenant.id) == None:
            raise fault.ItemNotFoundFault("The Global Tenant not found")

        if db_api.group_get(group) == None:
            raise fault.ItemNotFoundFault("The Group not found")
        duser = db_api.user_get(user)
        if duser == None:
            raise fault.ItemNotFoundFault("The User not found")

        if db_api.tenant_group_get(group, gtenant.id) == None:
            raise fault.ItemNotFoundFault("A global tenant group with "
                                          "that id not found")

        if db_api.user_get_by_group(user, group) == None:
            raise fault.ItemNotFoundFault("A user with that id in a "
                                          "group not found")

        db_api.user_tenant_group_delete(user, group)
        return None

    #

    def __get_auth_data(self, dtoken, duser):
        """return AuthData object for a token/user pair"""

        token = auth.Token(dtoken.expires, dtoken.token_id)

        gs = []
        for ug in duser.groups:
            dgroup = db_api.group_get(ug.group_id)
            gs.append(auth.Group(dgroup.id, dgroup.tenant_id))
        groups = auth.Groups(gs, [])
        if len(duser.tenants) == 0:
            raise fault.IDMFault("Strange: user %s is not associated "
                                 "with a tenant!" % duser.id)
        user = auth.User(duser.id, duser.tenants[0].tenant_id, groups)
        return auth.AuthData(token, user)

    def __validate_token(self, token_id, admin=True):
        if not token_id:
            raise fault.UnauthorizedFault("Missing token")
        (token, user) = self.__get_dauth_data(token_id)

        if not token:
            raise fault.UnauthorizedFault("Bad token, please reauthenticate")
        if token.expires < datetime.now():
            raise fault.UnauthorizedFault("Token expired, please renew")
        if not user.enabled:
            raise fault.UserDisabledFault("The user %s has been disabled!"
                                          % user.id)
        if admin:
            for ug in user.groups:
                if ug.group_id == "Admin":
                    return (token, user)
            raise fault.ForbiddenFault("You are not authorized "
                                       "to make this call")
        return (token, user)
