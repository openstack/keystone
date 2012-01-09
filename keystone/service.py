import json
import logging
import uuid

import routes
import webob.dec
import webob.exc

from keystone import identity
from keystone import token
from keystone import wsgi


HIGH_LEVEL_CALLS = {
    'authenticate': ('POST', '/tokens'),
    'get_tenants': ('GET', '/user/%(user_id)s/tenants'),
    'get_user': ('GET', '/user/%(user_id)s'),
    'get_tenant': ('GET', '/tenant/%(tenant_id)s'),
    'get_tenant_by_name': ('GET', '/tenant_name/%(tenant_name)s'),
    'get_extras': ('GET', '/extras/%(tenant_id)s-%(user_id)s'),
    'get_token': ('GET', '/token/%(token_id)s'),
    }

# NOTE(termie): creates are seperate from updates to allow duplication checks
LOW_LEVEL_CALLS = {
    # tokens
    'create_token': ('POST', '/token'),
    'delete_token': ('DELETE', '/token/%(token_id)s'),
    # users
    'create_user': ('POST', '/user'),
    'update_user': ('PUT', '/user/%(user_id)s'),
    'delete_user': ('DELETE', '/user/%(user_id)s'),
    # tenants
    'create_tenant': ('POST', '/tenant'),
    'update_tenant': ('PUT', '/tenant/%(tenant_id)s'),
    'delete_tenant': ('DELETE', '/tenant/%(tenant_id)s'),
    # extras
    # NOTE(termie): these separators are probably going to bite us eventually
    'create_extras': ('POST', '/extras'),
    'update_extras': ('PUT', '/extras/%(tenant_id)s-%(user_id)s'),
    'delete_extras': ('DELETE', '/extras/%(tenant_id)s-%(user_id)s'),
    }


URLMAP = HIGH_LEVEL_CALLS.copy()
URLMAP.update(LOW_LEVEL_CALLS)


class SmarterEncoder(json.JSONEncoder):
  def default(self, obj):
    if not isinstance(obj, dict) and hasattr(obj, 'iteritems'):
      return dict(obj.iteritems())
    return super(SmarterEncoder, self).default(obj)


class BaseApplication(wsgi.Application):
  @webob.dec.wsgify
  def __call__(self, req):
    arg_dict = req.environ['wsgiorg.routing_args'][1]
    action = arg_dict['action']
    del arg_dict['action']
    del arg_dict['controller']
    logging.debug('arg_dict: %s', arg_dict)

    context = req.environ.get('openstack.context', {})
    # allow middleware up the stack to override the params
    params = {}
    if 'openstack.params' in req.environ:
      params = req.environ['openstack.params']
    params.update(arg_dict)

    # TODO(termie): do some basic normalization on methods
    method = getattr(self, action)

    # NOTE(vish): make sure we have no unicode keys for py2.6.
    params = dict([(self._normalize_arg(k), v)
                   for (k, v) in params.iteritems()])
    result = method(context, **params)

    if result is None or type(result) is str or type(result) is unicode:
      return result
    elif isinstance(result, webob.exc.WSGIHTTPException):
      return result

    return self._serialize(result)

  def _serialize(self, result):
    return json.dumps(result, cls=SmarterEncoder)

  def _normalize_arg(self, arg):
    return str(arg).replace(':', '_').replace('-', '_')

  def _normalize_dict(self, d):
    return dict([(self._normalize_arg(k), v)
                 for (k, v) in d.iteritems()])

  def assert_admin(self, context):
    if not context['is_admin']:
      user_token_ref = self.token_api.get_token(
          context=context, token_id=context['token_id'])
      creds = user_token_ref['extras'].copy()
      creds['user_id'] = user_token_ref['user'].get('id')
      creds['tenant_id'] = user_token_ref['tenant'].get('id')
      print creds
      # Accept either is_admin or the admin role
      assert self.policy_api.can_haz(context,
                                     ('is_admin:1', 'roles:admin'),
                                      creds)


class TokenController(BaseApplication):
  """Validate and pass through calls to TokenManager."""

  def __init__(self):
    self.token_api = token.Manager()

  def validate_token(self, context, token_id):
    token_info = self.token_api.validate_token(context, token_id)
    if not token_info:
      raise webob.exc.HTTPUnauthorized()
    return token_info


class IdentityController(BaseApplication):
  """Validate and pass calls through to IdentityManager.

  IdentityManager will also pretty much just pass calls through to
  a specific driver.
  """

  def __init__(self):
    self.identity_api = identity.Manager()
    self.token_api = token.Manager()

  def noop(self, context, *args, **kw):
    return ''

  def authenticate(self, context, **kwargs):
    user_ref, tenant_ref, extras_ref = self.identity_api.authenticate(
        context, **kwargs)
    # TODO(termie): strip password from return values
    token_ref = self.token_api.create_token(context,
                                            dict(tenant=tenant_ref,
                                                 user=user_ref,
                                                 extras=extras_ref))
    logging.debug('TOKEN: %s', token_ref)
    return token_ref

  def get_tenants(self, context, user_id=None):
    token_id = context.get('token_id')
    token_ref = self.token_api.get_token(context, token_id)
    assert token_ref
    assert token_ref['user']['id'] == user_id
    tenants_ref = []
    for tenant_id in token_ref['user']['tenants']:
      tenants_ref.append(self.identity_api.get_tenant(context,
                                                      tenant_id))

    return tenants_ref

  # crud api
  def get_user(self, context, user_id):
    return self.identity_api.get_user(context, user_id=user_id)

  def create_user(self, context, **kw):
    user_id = kw.get('id') and kw.get('id') or uuid.uuid4().hex
    kw['id'] = user_id
    return self.identity_api.create_user(context, user_id=user_id, data=kw)

  def update_user(self, context, user_id, **kw):
    kw['id'] = user_id
    kw.pop('user_id', None)
    return self.identity_api.update_user(context, user_id=user_id, data=kw)

  def delete_user(self, context, user_id):
    return self.identity_api.delete_user(context, user_id=user_id)

  def get_tenant(self, context, tenant_id):
    return self.identity_api.get_tenant(context, tenant_id=tenant_id)

  def get_tenant_by_name(self, context, tenant_name):
    return self.identity_api.get_tenant_by_name(
        context, tenant_name=tenant_name)

  def create_tenant(self, context, **kw):
    tenant_id = kw.get('id') and kw.get('id') or uuid.uuid4().hex
    kw['id'] = tenant_id
    return self.identity_api.create_tenant(
        context, tenant_id=tenant_id, data=kw)

  def update_tenant(self, context, tenant_id, **kw):
    kw['id'] = tenant_id
    kw.pop('tenant_id', None)
    return self.identity_api.update_tenant(
        context, tenant_id=tenant_id, data=kw)

  def delete_tenant(self, context, tenant_id):
    return self.identity_api.delete_tenant(context, tenant_id=tenant_id)

  def get_extras(self, context, user_id, tenant_id):
    return self.identity_api.get_extras(
        context, user_id=user_id, tenant_id=tenant_id)

  def create_extras(self, context, **kw):
    user_id = kw.pop('user_id')
    tenant_id = kw.pop('tenant_id')
    return self.identity_api.create_extras(
        context, user_id=user_id, tenant_id=tenant_id, data=kw)

  def update_extras(self, context, user_id, tenant_id, **kw):
    kw.pop('user_id', None)
    kw.pop('tenant_id', None)
    return self.identity_api.update_extras(
        context, user_id=user_id, tenant_id=tenant_id, data=kw)

  def delete_extras(self, context, user_id, tenant_id):
    return self.identity_api.delete_extras(
        context, user_id=user_id, tenant_id=tenant_id)


class Router(wsgi.Router):
  def __init__(self):
    self.identity_controller = IdentityController()
    self.token_controller = TokenController()

    mapper = self._build_map(URLMAP)
    mapper.connect('/', controller=self.identity_controller, action='noop')
    super(Router, self).__init__(mapper)

  def _build_map(self, urlmap):
    """Build a routes.Mapper based on URLMAP."""
    mapper = routes.Mapper()
    for k, v in urlmap.iteritems():
      # NOTE(termie): hack
      if 'token' in k:
        controller = self.token_controller
      else:
        controller = self.identity_controller
        action = k
        method, path = v
        path = path.replace('%(', '{').replace(')s', '}')

        mapper.connect(path,
                       controller=controller,
                       action=action,
                       conditions=dict(method=[method]))

    return mapper


def app_factory(global_conf, **local_conf):
  #conf = global_conf.copy()
  #conf.update(local_conf)
  return Router()
