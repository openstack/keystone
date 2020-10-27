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

"""Notifications module for OpenStack Identity Service resources."""

import collections
import functools
import inspect
import socket

import flask
from oslo_log import log
import oslo_messaging
from oslo_utils import reflection
import pycadf
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import credential
from pycadf import eventfactory
from pycadf import host
from pycadf import reason
from pycadf import resource

from keystone.common import context
from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.i18n import _


_CATALOG_HELPER_OBJ = None

LOG = log.getLogger(__name__)
# NOTE(gyee): actions that can be notified. One must update this list whenever
# a new action is supported.
_ACTIONS = collections.namedtuple(
    'NotificationActions',
    'created, deleted, disabled, updated, internal')
ACTIONS = _ACTIONS(created='created', deleted='deleted', disabled='disabled',
                   updated='updated', internal='internal')
"""The actions on resources."""

CADF_TYPE_MAP = {
    'group': taxonomy.SECURITY_GROUP,
    'project': taxonomy.SECURITY_PROJECT,
    'role': taxonomy.SECURITY_ROLE,
    'user': taxonomy.SECURITY_ACCOUNT_USER,
    'domain': taxonomy.SECURITY_DOMAIN,
    'region': taxonomy.SECURITY_REGION,
    'endpoint': taxonomy.SECURITY_ENDPOINT,
    'service': taxonomy.SECURITY_SERVICE,
    'policy': taxonomy.SECURITY_POLICY,
    'OS-TRUST:trust': taxonomy.SECURITY_TRUST,
    'OS-OAUTH1:access_token': taxonomy.SECURITY_CREDENTIAL,
    'OS-OAUTH1:request_token': taxonomy.SECURITY_CREDENTIAL,
    'OS-OAUTH1:consumer': taxonomy.SECURITY_ACCOUNT,
    'application_credential': taxonomy.SECURITY_CREDENTIAL,
}

SAML_AUDIT_TYPE = 'http://docs.oasis-open.org/security/saml/v2.0'
# resource types that can be notified
_SUBSCRIBERS = {}
_notifier = None
SERVICE = 'identity'
PROVIDERS = provider_api.ProviderAPIs

ROOT_DOMAIN = '<<keystone.domain.root>>'

CONF = keystone.conf.CONF

# NOTE(morganfainberg): Special case notifications that are only used
# internally for handling token persistence token deletions
INVALIDATE_TOKEN_CACHE = 'invalidate_token_cache'  # nosec
PERSIST_REVOCATION_EVENT_FOR_USER = 'persist_revocation_event_for_user'
REMOVE_APP_CREDS_FOR_USER = 'remove_application_credentials_for_user'
DOMAIN_DELETED = 'domain_deleted'


def build_audit_initiator():
    """A pyCADF initiator describing the current authenticated context."""
    pycadf_host = host.Host(address=flask.request.remote_addr,
                            agent=str(flask.request.user_agent))
    initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER,
                                  host=pycadf_host)
    oslo_context = flask.request.environ.get(context.REQUEST_CONTEXT_ENV)
    if oslo_context.user_id:
        initiator.id = utils.resource_uuid(oslo_context.user_id)
        initiator.user_id = oslo_context.user_id

    if oslo_context.project_id:
        initiator.project_id = oslo_context.project_id

    if oslo_context.domain_id:
        initiator.domain_id = oslo_context.domain_id

    initiator.request_id = oslo_context.request_id

    if oslo_context.global_request_id:
        initiator.global_request_id = oslo_context.global_request_id

    return initiator


class Audit(object):
    """Namespace for audit notification functions.

    This is a namespace object to contain all of the direct notification
    functions utilized for ``Manager`` methods.
    """

    @classmethod
    def _emit(cls, operation, resource_type, resource_id, initiator, public,
              actor_dict=None, reason=None):
        """Directly send an event notification.

        :param operation: one of the values from ACTIONS
        :param resource_type: type of resource being affected
        :param resource_id: ID of the resource affected
        :param initiator: CADF representation of the user that created the
                          request
        :param public: If True (default), the event will be sent to the
                       notifier API.  If False, the event will only be sent via
                       notify_event_callbacks to in process listeners
        :param actor_dict: dictionary of actor information in the event of
                           assignment notification
        :param reason: pycadf object containing the response code and
                       message description
        """
        # NOTE(stevemar): the _send_notification function is
        # overloaded, it's used to register callbacks and to actually
        # send the notification externally. Thus, we should check
        # the desired notification format in the function instead
        # of before it.
        _send_notification(
            operation,
            resource_type,
            resource_id,
            initiator=initiator,
            actor_dict=actor_dict,
            public=public)

        if CONF.notification_format == 'cadf' and public:
            outcome = taxonomy.OUTCOME_SUCCESS
            _create_cadf_payload(operation, resource_type, resource_id,
                                 outcome, initiator, reason)

    @classmethod
    def created(cls, resource_type, resource_id, initiator=None,
                public=True, reason=None):
        cls._emit(ACTIONS.created, resource_type, resource_id, initiator,
                  public, reason=reason)

    @classmethod
    def updated(cls, resource_type, resource_id, initiator=None,
                public=True, reason=None):
        cls._emit(ACTIONS.updated, resource_type, resource_id, initiator,
                  public, reason=reason)

    @classmethod
    def disabled(cls, resource_type, resource_id, initiator=None,
                 public=True, reason=None):
        cls._emit(ACTIONS.disabled, resource_type, resource_id, initiator,
                  public, reason=reason)

    @classmethod
    def deleted(cls, resource_type, resource_id, initiator=None,
                public=True, reason=None):
        cls._emit(ACTIONS.deleted, resource_type, resource_id, initiator,
                  public, reason=reason)

    @classmethod
    def added_to(cls, target_type, target_id, actor_type, actor_id,
                 initiator=None, public=True, reason=None):
        actor_dict = {'id': actor_id,
                      'type': actor_type,
                      'actor_operation': 'added'}
        cls._emit(ACTIONS.updated, target_type, target_id, initiator, public,
                  actor_dict=actor_dict, reason=reason)

    @classmethod
    def removed_from(cls, target_type, target_id, actor_type, actor_id,
                     initiator=None, public=True, reason=None):
        actor_dict = {'id': actor_id,
                      'type': actor_type,
                      'actor_operation': 'removed'}
        cls._emit(ACTIONS.updated, target_type, target_id, initiator, public,
                  actor_dict=actor_dict, reason=reason)

    @classmethod
    def internal(cls, resource_type, resource_id, reason=None):
        # NOTE(lbragstad): Internal notifications are never public and have
        # never used the initiator variable, but the _emit() method expects
        # them. Let's set them here but not expose them through the method
        # signature - that way someone can not do something like send an
        # internal notification publicly.
        initiator = None
        public = False
        cls._emit(ACTIONS.internal, resource_type, resource_id, initiator,
                  public, reason)


def invalidate_token_cache_notification(reason):
    """A specific notification for invalidating the token cache.

    :param reason: The specific reason why the token cache is being
                   invalidated.
    :type reason: string

    """
    # Since keystone does a lot of work in the authentication and validation
    # process to make sure the authorization context for the user is
    # update-to-date, invalidating the token cache is a somewhat common
    # operation. It's done across various subsystems when role assignments
    # change, users are disabled, identity providers deleted or disabled, etc..
    # This notification is meant to make the process of invalidating the token
    # cache DRY, instead of have each subsystem implement their own token cache
    # invalidation strategy or callbacks.
    LOG.debug(reason)
    resource_id = None
    initiator = None
    public = False
    Audit._emit(
        ACTIONS.internal, INVALIDATE_TOKEN_CACHE, resource_id, initiator,
        public, reason=reason
    )


def _get_callback_info(callback):
    """Return list containing callback's module and name.

    If the callback is a bound instance method also return the class name.

    :param callback: Function to call
    :type callback: function
    :returns: List containing parent module, (optional class,) function name
    :rtype: list
    """
    module_name = getattr(callback, '__module__', None)
    func_name = callback.__name__
    if inspect.ismethod(callback):
        class_name = reflection.get_class_name(callback.__self__,
                                               fully_qualified=False)
        return [module_name, class_name, func_name]
    else:
        return [module_name, func_name]


def register_event_callback(event, resource_type, callbacks):
    """Register each callback with the event.

    :param event: Action being registered
    :type event: keystone.notifications.ACTIONS
    :param resource_type: Type of resource being operated on
    :type resource_type: str
    :param callbacks: Callback items to be registered with event
    :type callbacks: list
    :raises ValueError: If event is not a valid ACTION
    :raises TypeError: If callback is not callable
    """
    if event not in ACTIONS:
        raise ValueError(_('%(event)s is not a valid notification event, must '
                           'be one of: %(actions)s') %
                         {'event': event, 'actions': ', '.join(ACTIONS)})

    if not hasattr(callbacks, '__iter__'):
        callbacks = [callbacks]

    for callback in callbacks:
        if not callable(callback):
            msg = 'Method not callable: %s' % callback
            tr_msg = _('Method not callable: %s') % callback
            LOG.error(msg)
            raise TypeError(tr_msg)
        _SUBSCRIBERS.setdefault(event, {}).setdefault(resource_type, set())
        _SUBSCRIBERS[event][resource_type].add(callback)

        if LOG.logger.getEffectiveLevel() <= log.DEBUG:
            # Do this only if its going to appear in the logs.
            msg = 'Callback: `%(callback)s` subscribed to event `%(event)s`.'
            callback_info = _get_callback_info(callback)
            callback_str = '.'.join(i for i in callback_info if i is not None)
            event_str = '.'.join(['identity', resource_type, event])
            LOG.debug(msg, {'callback': callback_str, 'event': event_str})


def listener(cls):
    """A class decorator to declare a class to be a notification listener.

    A notification listener must specify the event(s) it is interested in by
    defining a ``event_callbacks`` attribute or property. ``event_callbacks``
    is a dictionary where the key is the type of event and the value is a
    dictionary containing a mapping of resource types to callback(s).

    :data:`.ACTIONS` contains constants for the currently
    supported events. There is currently no single place to find constants for
    the resource types.

    Example::

        @listener
        class Something(object):

            def __init__(self):
                self.event_callbacks = {
                    notifications.ACTIONS.created: {
                        'user': self._user_created_callback,
                    },
                    notifications.ACTIONS.deleted: {
                        'project': [
                            self._project_deleted_callback,
                            self._do_cleanup,
                        ]
                    },
                }

    """
    def init_wrapper(init):
        @functools.wraps(init)
        def __new_init__(self, *args, **kwargs):
            init(self, *args, **kwargs)
            _register_event_callbacks(self)
        return __new_init__

    def _register_event_callbacks(self):
        for event, resource_types in self.event_callbacks.items():
            for resource_type, callbacks in resource_types.items():
                register_event_callback(event, resource_type, callbacks)

    cls.__init__ = init_wrapper(cls.__init__)
    return cls


def notify_event_callbacks(service, resource_type, operation, payload):
    """Send a notification to registered extensions."""
    if operation in _SUBSCRIBERS:
        if resource_type in _SUBSCRIBERS[operation]:
            for cb in _SUBSCRIBERS[operation][resource_type]:
                subst_dict = {'cb_name': cb.__name__,
                              'service': service,
                              'resource_type': resource_type,
                              'operation': operation,
                              'payload': payload}
                LOG.debug('Invoking callback %(cb_name)s for event '
                          '%(service)s %(resource_type)s %(operation)s for '
                          '%(payload)s', subst_dict)
                cb(service, resource_type, operation, payload)


def _get_notifier():
    """Return a notifier object.

    If _notifier is None it means that a notifier object has not been set.
    If _notifier is False it means that a notifier has previously failed to
    construct.
    Otherwise it is a constructed Notifier object.
    """
    global _notifier

    if _notifier is None:
        host = CONF.default_publisher_id or socket.gethostname()
        try:
            transport = oslo_messaging.get_notification_transport(CONF)
            _notifier = oslo_messaging.Notifier(transport,
                                                "identity.%s" % host)
        except Exception:
            LOG.exception("Failed to construct notifier")
            _notifier = False

    return _notifier


def clear_subscribers():
    """Empty subscribers dictionary.

    This effectively stops notifications since there will be no subscribers
    to publish to.
    """
    _SUBSCRIBERS.clear()


def reset_notifier():
    """Reset the notifications internal state.

    This is used only for testing purposes.

    """
    global _notifier
    _notifier = None


def _create_cadf_payload(operation, resource_type, resource_id,
                         outcome, initiator, reason=None):
    """Prepare data for CADF audit notifier.

    Transform the arguments into content to be consumed by the function that
    emits CADF events (_send_audit_notification). Specifically the
    ``resource_type`` (role, user, etc) must be transformed into a CADF
    keyword, such as: ``data/security/role``. The ``resource_id`` is added as a
    top level value for the ``resource_info`` key. Lastly, the ``operation`` is
    used to create the CADF ``action``, and the ``event_type`` name.

    As per the CADF specification, the ``action`` must start with create,
    update, delete, etc... i.e.: created.user or deleted.role

    However the ``event_type`` is an OpenStack-ism that is typically of the
    form project.resource.operation. i.e.: identity.project.updated

    :param operation: operation being performed (created, updated, or deleted)
    :param resource_type: type of resource being operated on (role, user, etc)
    :param resource_id: ID of resource being operated on
    :param outcome: outcomes of the operation (SUCCESS, FAILURE, etc)
    :param initiator: CADF representation of the user that created the request
    :param reason: pycadf object containing the response code and
                   message description
    """
    if resource_type not in CADF_TYPE_MAP:
        target_uri = taxonomy.UNKNOWN
    else:
        target_uri = CADF_TYPE_MAP.get(resource_type)

    # TODO(gagehugo): The root domain ID is typically hidden, there isn't a
    # reason to emit a notification for it. Once we expose the root domain
    # (and handle the CADF UUID), remove this.
    if resource_id == ROOT_DOMAIN:
        return

    target = resource.Resource(typeURI=target_uri,
                               id=resource_id)

    audit_kwargs = {'resource_info': resource_id}
    cadf_action = '%s.%s' % (operation, resource_type)
    event_type = '%s.%s.%s' % (SERVICE, resource_type, operation)

    _send_audit_notification(cadf_action, initiator, outcome,
                             target, event_type, reason=reason, **audit_kwargs)


def _send_notification(operation, resource_type, resource_id, initiator=None,
                       actor_dict=None, public=True):
    """Send notification to inform observers about the affected resource.

    This method doesn't raise an exception when sending the notification fails.

    :param operation: operation being performed (created, updated, or deleted)
    :param resource_type: type of resource being operated on
    :param resource_id: ID of resource being operated on
    :param initiator: representation of the user that created the request
    :param actor_dict: a dictionary containing the actor's ID and type
    :param public:  if True (default), the event will be sent
                    to the notifier API.
                    if False, the event will only be sent via
                    notify_event_callbacks to in process listeners.
    """
    payload = {'resource_info': resource_id}

    if actor_dict:
        payload['actor_id'] = actor_dict['id']
        payload['actor_type'] = actor_dict['type']
        payload['actor_operation'] = actor_dict['actor_operation']

    if initiator:
        payload['request_id'] = initiator.request_id
        global_request_id = getattr(initiator, 'global_request_id', None)
        if global_request_id:
            payload['global_request_id'] = global_request_id

    notify_event_callbacks(SERVICE, resource_type, operation, payload)

    # Only send this notification if the 'basic' format is used, otherwise
    # let the CADF functions handle sending the notification. But we check
    # here so as to not disrupt the notify_event_callbacks function.
    if public and CONF.notification_format == 'basic':
        notifier = _get_notifier()
        if notifier:
            context = {}
            event_type = '%(service)s.%(resource_type)s.%(operation)s' % {
                'service': SERVICE,
                'resource_type': resource_type,
                'operation': operation}
            if _check_notification_opt_out(event_type, outcome=None):
                return
            try:
                notifier.info(context, event_type, payload)
            except Exception:
                LOG.exception(
                    'Failed to send %(res_id)s %(event_type)s notification',
                    {'res_id': resource_id, 'event_type': event_type})


def _get_request_audit_info(context, user_id=None):
    """Collect audit information about the request used for CADF.

    :param context: Request context
    :param user_id: Optional user ID, alternatively collected from context
    :returns: Auditing data about the request
    :rtype: :class:`pycadf.Resource`
    """
    remote_addr = None
    http_user_agent = None
    project_id = None
    domain_id = None

    if context and 'environment' in context and context['environment']:
        environment = context['environment']
        remote_addr = environment.get('REMOTE_ADDR')
        http_user_agent = environment.get('HTTP_USER_AGENT')
        if not user_id:
            user_id = environment.get('KEYSTONE_AUTH_CONTEXT',
                                      {}).get('user_id')
        project_id = environment.get('KEYSTONE_AUTH_CONTEXT',
                                     {}).get('project_id')
        domain_id = environment.get('KEYSTONE_AUTH_CONTEXT',
                                    {}).get('domain_id')

    host = pycadf.host.Host(address=remote_addr, agent=http_user_agent)
    initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER, host=host)

    if user_id:
        initiator.user_id = user_id
        initiator.id = utils.resource_uuid(user_id)
        initiator = _add_username_to_initiator(initiator)

    if project_id:
        initiator.project_id = project_id
    if domain_id:
        initiator.domain_id = domain_id

    return initiator


class CadfNotificationWrapper(object):
    """Send CADF event notifications for various methods.

    This function is only used for Authentication events. Its ``action`` and
    ``event_type`` are dictated below.

    - action: ``authenticate``
    - event_type: ``identity.authenticate``

    Sends CADF notifications for events such as whether an authentication was
    successful or not.

    :param operation: The authentication related action being performed

    """

    def __init__(self, operation):
        self.action = operation
        self.event_type = '%s.%s' % (SERVICE, operation)

    def __call__(self, f):
        @functools.wraps(f)
        def wrapper(wrapped_self, user_id, *args, **kwargs):
            """Will always send a notification."""
            target = resource.Resource(typeURI=taxonomy.ACCOUNT_USER)
            initiator = build_audit_initiator()
            initiator.user_id = user_id
            initiator = _add_username_to_initiator(initiator)
            initiator.id = utils.resource_uuid(user_id)
            try:
                result = f(wrapped_self, user_id, *args, **kwargs)
            except (exception.AccountLocked,
                    exception.PasswordExpired) as ex:
                # Send a CADF event with a reason for PCI-DSS related
                # authentication failures
                audit_reason = reason.Reason(str(ex), str(ex.code))
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_FAILURE,
                                         target, self.event_type,
                                         reason=audit_reason)
                if isinstance(ex, exception.AccountLocked):
                    raise exception.Unauthorized
                raise
            except Exception:
                # For authentication failure send a CADF event as well
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_FAILURE,
                                         target, self.event_type)
                raise
            else:
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_SUCCESS,
                                         target, self.event_type)
                return result

        return wrapper


class CadfRoleAssignmentNotificationWrapper(object):
    """Send CADF notifications for ``role_assignment`` methods.

    This function is only used for role assignment events. Its ``action`` and
    ``event_type`` are dictated below.

    - action: ``created.role_assignment`` or ``deleted.role_assignment``
    - event_type: ``identity.role_assignment.created`` or
        ``identity.role_assignment.deleted``

    Sends a CADF notification if the wrapped method does not raise an
    :class:`Exception` (such as :class:`keystone.exception.NotFound`).

    :param operation: one of the values from ACTIONS (created or deleted)
    """

    ROLE_ASSIGNMENT = 'role_assignment'

    def __init__(self, operation):
        self.action = '%s.%s' % (operation, self.ROLE_ASSIGNMENT)
        self.event_type = '%s.%s.%s' % (SERVICE, self.ROLE_ASSIGNMENT,
                                        operation)

    def __call__(self, f):
        @functools.wraps(f)
        def wrapper(wrapped_self, role_id, *args, **kwargs):
            """Send a notification if the wrapped callable is successful.

            NOTE(stevemar): The reason we go through checking kwargs
            and args for possible target and actor values is because the
            create_grant() (and delete_grant()) method are called
            differently in various tests.
            Using named arguments, i.e.::

                create_grant(user_id=user['id'], domain_id=domain['id'],
                             role_id=role['id'])

            Or, using positional arguments, i.e.::

                create_grant(role_id['id'], user['id'], None,
                             domain_id=domain['id'], None)

            Or, both, i.e.::

                create_grant(role_id['id'], user_id=user['id'],
                             domain_id=domain['id'])

            Checking the values for kwargs is easy enough, since it comes
            in as a dictionary

            The actual method signature is

            ::

                create_grant(role_id, user_id=None, group_id=None,
                             domain_id=None, project_id=None,
                             inherited_to_projects=False)

            So, if the values of actor or target are still None after
            checking kwargs, we can check the positional arguments,
            based on the method signature.
            """
            call_args = inspect.getcallargs(
                f, wrapped_self, role_id, *args, **kwargs)
            inherited = call_args['inherited_to_projects']
            initiator = call_args.get('initiator', None)
            target = resource.Resource(typeURI=taxonomy.ACCOUNT_USER)

            audit_kwargs = {}
            if call_args['project_id']:
                audit_kwargs['project'] = call_args['project_id']
            elif call_args['domain_id']:
                audit_kwargs['domain'] = call_args['domain_id']

            if call_args['user_id']:
                audit_kwargs['user'] = call_args['user_id']
            elif call_args['group_id']:
                audit_kwargs['group'] = call_args['group_id']

            audit_kwargs['inherited_to_projects'] = inherited
            audit_kwargs['role'] = role_id

            try:
                result = f(wrapped_self, role_id, *args, **kwargs)
            except Exception:
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_FAILURE,
                                         target, self.event_type,
                                         **audit_kwargs)
                raise
            else:
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_SUCCESS,
                                         target, self.event_type,
                                         **audit_kwargs)
                return result

        return wrapper


def send_saml_audit_notification(action, user_id, group_ids,
                                 identity_provider, protocol, token_id,
                                 outcome):
    """Send notification to inform observers about SAML events.

    :param action: Action being audited
    :type action: str
    :param user_id: User ID from Keystone token
    :type user_id: str
    :param group_ids: List of Group IDs from Keystone token
    :type group_ids: list
    :param identity_provider: ID of the IdP from the Keystone token
    :type identity_provider: str or None
    :param protocol: Protocol ID for IdP from the Keystone token
    :type protocol: str
    :param token_id: audit_id from Keystone token
    :type token_id: str or None
    :param outcome: One of :class:`pycadf.cadftaxonomy`
    :type outcome: str
    """
    initiator = build_audit_initiator()
    target = resource.Resource(typeURI=taxonomy.ACCOUNT_USER)
    audit_type = SAML_AUDIT_TYPE
    user_id = user_id or taxonomy.UNKNOWN
    token_id = token_id or taxonomy.UNKNOWN
    group_ids = group_ids or []
    cred = credential.FederatedCredential(token=token_id, type=audit_type,
                                          identity_provider=identity_provider,
                                          user=user_id, groups=group_ids)
    initiator.credential = cred
    event_type = '%s.%s' % (SERVICE, action)
    _send_audit_notification(action, initiator, outcome, target, event_type)


class _CatalogHelperObj(provider_api.ProviderAPIMixin, object):
    """A helper object to allow lookups of identity service id."""


def _send_audit_notification(action, initiator, outcome, target,
                             event_type, reason=None, **kwargs):
    """Send CADF notification to inform observers about the affected resource.

    This method logs an exception when sending the notification fails.

    :param action: CADF action being audited (e.g., 'authenticate')
    :param initiator: CADF resource representing the initiator
    :param outcome: The CADF outcome (taxonomy.OUTCOME_PENDING,
        taxonomy.OUTCOME_SUCCESS, taxonomy.OUTCOME_FAILURE)
    :param target: CADF resource representing the target
    :param event_type: An OpenStack-ism, typically this is the meter name that
        Ceilometer uses to poll events.
    :param kwargs: Any additional arguments passed in will be added as
        key-value pairs to the CADF event.
    :param reason: Reason for the notification which contains the response
        code and message description
    """
    if _check_notification_opt_out(event_type, outcome):
        return

    global _CATALOG_HELPER_OBJ
    if _CATALOG_HELPER_OBJ is None:
        _CATALOG_HELPER_OBJ = _CatalogHelperObj()
    service_list = _CATALOG_HELPER_OBJ.catalog_api.list_services()
    service_id = None

    for i in service_list:
        if i['type'] == SERVICE:
            service_id = i['id']
            break

    initiator = _add_username_to_initiator(initiator)

    event = eventfactory.EventFactory().new_event(
        eventType=cadftype.EVENTTYPE_ACTIVITY,
        outcome=outcome,
        action=action,
        initiator=initiator,
        target=target,
        reason=reason,
        observer=resource.Resource(typeURI=taxonomy.SERVICE_SECURITY))

    if service_id is not None:
        event.observer.id = service_id

    for key, value in kwargs.items():
        setattr(event, key, value)

    context = {}
    payload = event.as_dict()
    notifier = _get_notifier()

    if notifier:
        try:
            notifier.info(context, event_type, payload)
        except Exception:
            # diaper defense: any exception that occurs while emitting the
            # notification should not interfere with the API request
            LOG.exception(
                'Failed to send %(action)s %(event_type)s notification',
                {'action': action, 'event_type': event_type})


def _check_notification_opt_out(event_type, outcome):
    """Check if a particular event_type has been opted-out of.

    This method checks to see if an event should be sent to the messaging
    service. Any event specified in the opt-out list will not be transmitted.

    :param event_type: This is the meter name that Ceilometer uses to poll
        events. For example: identity.user.created, or
        identity.authenticate.success, or identity.role_assignment.created
    :param outcome: The CADF outcome (taxonomy.OUTCOME_PENDING,
        taxonomy.OUTCOME_SUCCESS, taxonomy.OUTCOME_FAILURE)

    """
    # NOTE(stevemar): Special handling for authenticate, we look at the outcome
    # as well when evaluating. For authN events, event_type is just
    # identity.authenticate, which isn't fine enough to provide any opt-out
    # value, so we attach the outcome to re-create the meter name used in
    # ceilometer.
    if 'authenticate' in event_type:
        event_type = event_type + "." + outcome

    if event_type in CONF.notification_opt_out:
        return True

    return False


def _add_username_to_initiator(initiator):
    """Add the username to the initiator if missing."""
    if hasattr(initiator, 'username'):
        return initiator
    try:
        user_ref = PROVIDERS.identity_api.get_user(initiator.user_id)
        initiator.username = user_ref['name']
    except (exception.UserNotFound, AttributeError):
        # Either user not found or no user_id, move along
        pass

    return initiator


emit_event = CadfNotificationWrapper


role_assignment = CadfRoleAssignmentNotificationWrapper
