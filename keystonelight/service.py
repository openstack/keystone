import json
import logging
import uuid

import routes
import webob.dec
import webob.exc

from keystonelight import identity
from keystonelight import token
from keystonelight import utils
from keystonelight import wsgi


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
    params = dict([(str(k), v) for (k, v) in params.iteritems()])
    result = method(context, **params)

    if result is None or type(result) is str or type(result) is unicode:
      return result

    return json.dumps(result)


class TokenController(BaseApplication):
  """Validate and pass through calls to TokenManager."""

  def __init__(self, options):
    self.token_api = token.Manager(options=options)
    self.options = options

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

  def __init__(self, options):
    self.identity_api = identity.Manager(options=options)
    self.token_api = token.Manager(options=options)
    self.options = options

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

  def get_user(self, context, user_id):
    return self.identity_api.get_user(context, user_id=user_id)

  def create_user(self, context, **kw):
    user_id = uuid.uuid4().hex
    kw['id'] = user_id
    return self.identity_api.create_user(context, user_id=user_id, data=kw)

  def update_user(self, context, user_id, **kw):
    kw['id'] = user_id
    kw.pop('user_id', None)
    return self.identity_api.update_user(context, user_id=user_id, data=kw)

  def delete_user(self, context, user_id):
    return self.identity_api.delete_user(context, user_id=user_id)


class Router(wsgi.Router):
  def __init__(self, options):
    self.options = options
    self.identity_controller = IdentityController(options)
    self.token_controller = TokenController(options)

    mapper = self._build_map(URLMAP)
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
  conf = global_conf.copy()
  conf.update(local_conf)
  return Router(conf)
