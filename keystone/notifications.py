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

"""Notifications module for OpenStack Identity Service resources"""

import collections
import functools
import inspect
import logging
import socket

from oslo_config import cfg
from oslo_log import log
from oslo_log import versionutils
import oslo_messaging
import pycadf
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import credential
from pycadf import eventfactory
from pycadf import resource

from keystone.i18n import _, _LE


notifier_opts = [
    cfg.StrOpt('default_publisher_id',
               help='Default publisher_id for outgoing notifications'),
    cfg.StrOpt('notification_format', default='basic',
               choices=['basic', 'cadf'],
               help='Define the notification format for Identity Service '
                    'events. A "basic" notification has information about '
                    'the resource being operated on. A "cadf" notification '
                    'has the same information, as well as information about '
                    'the initiator of the event.'),
]

config_section = None
list_opts = lambda: [(config_section, notifier_opts), ]

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
}

SAML_AUDIT_TYPE = 'http://docs.oasis-open.org/security/saml/v2.0'
# resource types that can be notified
_SUBSCRIBERS = {}
_notifier = None
SERVICE = 'identity'


CONF = cfg.CONF
CONF.register_opts(notifier_opts)

# NOTE(morganfainberg): Special case notifications that are only used
# internally for handling token persistence token deletions
INVALIDATE_USER_TOKEN_PERSISTENCE = 'invalidate_user_tokens'
INVALIDATE_USER_PROJECT_TOKEN_PERSISTENCE = 'invalidate_user_project_tokens'
INVALIDATE_USER_OAUTH_CONSUMER_TOKENS = 'invalidate_user_consumer_tokens'


class Audit(object):
    """Namespace for audit notification functions.

    This is a namespace object to contain all of the direct notification
    functions utilized for ``Manager`` methods.
    """

    @classmethod
    def _emit(cls, operation, resource_type, resource_id, initiator, public):
        """Directly send an event notification.

        :param operation: one of the values from ACTIONS
        :param resource_type: type of resource being affected
        :param resource_id: ID of the resource affected
        :param initiator: CADF representation of the user that created the
                          request
        :param public: If True (default), the event will be sent to the
                       notifier API.  If False, the event will only be sent via
                       notify_event_callbacks to in process listeners
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
            public=public)

        if CONF.notification_format == 'cadf' and public:
            outcome = taxonomy.OUTCOME_SUCCESS
            _create_cadf_payload(operation, resource_type, resource_id,
                                 outcome, initiator)

    @classmethod
    def created(cls, resource_type, resource_id, initiator=None,
                public=True):
        cls._emit(ACTIONS.created, resource_type, resource_id, initiator,
                  public)

    @classmethod
    def updated(cls, resource_type, resource_id, initiator=None,
                public=True):
        cls._emit(ACTIONS.updated, resource_type, resource_id, initiator,
                  public)

    @classmethod
    def disabled(cls, resource_type, resource_id, initiator=None,
                 public=True):
        cls._emit(ACTIONS.disabled, resource_type, resource_id, initiator,
                  public)

    @classmethod
    def deleted(cls, resource_type, resource_id, initiator=None,
                public=True):
        cls._emit(ACTIONS.deleted, resource_type, resource_id, initiator,
                  public)


class ManagerNotificationWrapper(object):
    """Send event notifications for ``Manager`` methods.

    Sends a notification if the wrapped Manager method does not raise an
    ``Exception`` (such as ``keystone.exception.NotFound``).

    :param operation:  one of the values from ACTIONS
    :param resource_type: type of resource being affected
    :param public:  If True (default), the event will be sent to the notifier
                API.  If False, the event will only be sent via
                notify_event_callbacks to in process listeners

    """
    def __init__(self, operation, resource_type, public=True,
                 resource_id_arg_index=1, result_id_arg_attr=None):
        self.operation = operation
        self.resource_type = resource_type
        self.public = public
        self.resource_id_arg_index = resource_id_arg_index
        self.result_id_arg_attr = result_id_arg_attr

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            """Send a notification if the wrapped callable is successful."""
            try:
                result = f(*args, **kwargs)
            except Exception:
                raise
            else:
                if self.result_id_arg_attr is not None:
                    resource_id = result[self.result_id_arg_attr]
                else:
                    resource_id = args[self.resource_id_arg_index]

                # NOTE(stevemar): the _send_notification function is
                # overloaded, it's used to register callbacks and to actually
                # send the notification externally. Thus, we should check
                # the desired notification format in the function instead
                # of before it.
                _send_notification(
                    self.operation,
                    self.resource_type,
                    resource_id,
                    public=self.public)

                # Only emit CADF notifications for public events
                if CONF.notification_format == 'cadf' and self.public:
                    outcome = taxonomy.OUTCOME_SUCCESS
                    # NOTE(morganfainberg): The decorator form will always use
                    # a 'None' initiator, since we do not pass context around
                    # in a manner that allows the decorator to inspect context
                    # and extract the needed information.
                    initiator = None
                    _create_cadf_payload(self.operation, self.resource_type,
                                         resource_id, outcome, initiator)
            return result

        return wrapper


def created(*args, **kwargs):
    """Decorator to send notifications for ``Manager.create_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.created, *args, **kwargs)


def updated(*args, **kwargs):
    """Decorator to send notifications for ``Manager.update_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.updated, *args, **kwargs)


def disabled(*args, **kwargs):
    """Decorator to send notifications when an object is disabled."""
    return ManagerNotificationWrapper(ACTIONS.disabled, *args, **kwargs)


def deleted(*args, **kwargs):
    """Decorator to send notifications for ``Manager.delete_*`` methods."""
    return ManagerNotificationWrapper(ACTIONS.deleted, *args, **kwargs)


def internal(*args, **kwargs):
    """Decorator to send notifications for internal notifications only."""
    kwargs['public'] = False
    return ManagerNotificationWrapper(ACTIONS.internal, *args, **kwargs)


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
        class_name = callback.__self__.__class__.__name__
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
            msg = _('Method not callable: %s') % callback
            LOG.error(msg)
            raise TypeError(msg)
        _SUBSCRIBERS.setdefault(event, {}).setdefault(resource_type, set())
        _SUBSCRIBERS[event][resource_type].add(callback)

        if LOG.logger.getEffectiveLevel() <= logging.DEBUG:
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
    """Sends a notification to registered extensions."""
    if operation in _SUBSCRIBERS:
        if resource_type in _SUBSCRIBERS[operation]:
            for cb in _SUBSCRIBERS[operation][resource_type]:
                subst_dict = {'cb_name': cb.__name__,
                              'service': service,
                              'resource_type': resource_type,
                              'operation': operation,
                              'payload': payload}
                LOG.debug('Invoking callback %(cb_name)s for event '
                          '%(service)s %(resource_type)s %(operation)s for'
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
            transport = oslo_messaging.get_transport(CONF)
            _notifier = oslo_messaging.Notifier(transport,
                                                "identity.%s" % host)
        except Exception:
            LOG.exception(_LE("Failed to construct notifier"))
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
                         outcome, initiator):
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
    """

    if resource_type not in CADF_TYPE_MAP:
        target_uri = taxonomy.UNKNOWN
    else:
        target_uri = CADF_TYPE_MAP.get(resource_type)
    target = resource.Resource(typeURI=target_uri,
                               id=resource_id)

    audit_kwargs = {'resource_info': resource_id}
    cadf_action = '%s.%s' % (operation, resource_type)
    event_type = '%s.%s.%s' % (SERVICE, resource_type, operation)

    _send_audit_notification(cadf_action, initiator, outcome,
                             target, event_type, **audit_kwargs)


def _send_notification(operation, resource_type, resource_id, public=True):
    """Send notification to inform observers about the affected resource.

    This method doesn't raise an exception when sending the notification fails.

    :param operation: operation being performed (created, updated, or deleted)
    :param resource_type: type of resource being operated on
    :param resource_id: ID of resource being operated on
    :param public:  if True (default), the event will be sent
                    to the notifier API.
                    if False, the event will only be sent via
                    notify_event_callbacks to in process listeners.
    """
    payload = {'resource_info': resource_id}

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
            try:
                notifier.info(context, event_type, payload)
            except Exception:
                LOG.exception(_LE(
                    'Failed to send %(res_id)s %(event_type)s notification'),
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
    initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER,
                                  id=user_id, host=host)
    if project_id:
        initiator.project_id = project_id
    if domain_id:
        initiator.domain_id = domain_id

    return initiator


class CadfNotificationWrapper(object):
    """Send CADF event notifications for various methods.

    This function is only used for Authentication events. Its ``action`` and
    ``event_type`` are dictated below.

    - action: authenticate
    - event_type: identity.authenticate

    Sends CADF notifications for events such as whether an authentication was
    successful or not.

    :param operation: The authentication related action being performed

    """

    def __init__(self, operation):
        self.action = operation
        self.event_type = '%s.%s' % (SERVICE, operation)

    def __call__(self, f):
        def wrapper(wrapped_self, context, user_id, *args, **kwargs):
            """Always send a notification."""

            initiator = _get_request_audit_info(context, user_id)
            target = resource.Resource(typeURI=taxonomy.ACCOUNT_USER)
            try:
                result = f(wrapped_self, context, user_id, *args, **kwargs)
            except Exception:
                # For authentication failure send a cadf event as well
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

    - action: created.role_assignment or deleted.role_assignment
    - event_type: identity.role_assignment.created or
        identity.role_assignment.deleted

    Sends a CADF notification if the wrapped method does not raise an
    ``Exception`` (such as ``keystone.exception.NotFound``).

    :param operation: one of the values from ACTIONS (create or delete)
    """

    ROLE_ASSIGNMENT = 'role_assignment'

    def __init__(self, operation):
        self.action = '%s.%s' % (operation, self.ROLE_ASSIGNMENT)
        self.deprecated_event_type = '%s.%s.%s' % (SERVICE, operation,
                                                   self.ROLE_ASSIGNMENT)
        self.event_type = '%s.%s.%s' % (SERVICE, self.ROLE_ASSIGNMENT,
                                        operation)

    def __call__(self, f):
        def wrapper(wrapped_self, role_id, *args, **kwargs):
            """Send a notification if the wrapped callable is successful."""

            """ NOTE(stevemar): The reason we go through checking kwargs
            and args for possible target and actor values is because the
            create_grant() (and delete_grant()) method are called
            differently in various tests.
            Using named arguments, i.e.:
                create_grant(user_id=user['id'], domain_id=domain['id'],
                             role_id=role['id'])

            Or, using positional arguments, i.e.:
                create_grant(role_id['id'], user['id'], None,
                             domain_id=domain['id'], None)

            Or, both, i.e.:
                create_grant(role_id['id'], user_id=user['id'],
                             domain_id=domain['id'])

            Checking the values for kwargs is easy enough, since it comes
            in as a dictionary

            The actual method signature is
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
            context = call_args['context']

            initiator = _get_request_audit_info(context)
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

            # For backward compatibility, send both old and new event_type.
            # Deprecate old format and remove it in the next release.
            event_types = [self.deprecated_event_type, self.event_type]
            versionutils.deprecated(
                as_of=versionutils.deprecated.KILO,
                remove_in=+1,
                what=('sending duplicate %s notification event type' %
                      self.deprecated_event_type),
                in_favor_of='%s notification event type' % self.event_type)
            try:
                result = f(wrapped_self, role_id, *args, **kwargs)
            except Exception:
                for event_type in event_types:
                    _send_audit_notification(self.action, initiator,
                                             taxonomy.OUTCOME_FAILURE,
                                             target, event_type,
                                             **audit_kwargs)
                raise
            else:
                for event_type in event_types:
                    _send_audit_notification(self.action, initiator,
                                             taxonomy.OUTCOME_SUCCESS,
                                             target, event_type,
                                             **audit_kwargs)
                return result

        return wrapper


def send_saml_audit_notification(action, context, user_id, group_ids,
                                 identity_provider, protocol, token_id,
                                 outcome):
    """Send notification to inform observers about SAML events.

    :param action: Action being audited
    :type action: str
    :param context: Current request context to collect request info from
    :type context: dict
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

    initiator = _get_request_audit_info(context)
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


def _send_audit_notification(action, initiator, outcome, target,
                             event_type, **kwargs):
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

    """

    event = eventfactory.EventFactory().new_event(
        eventType=cadftype.EVENTTYPE_ACTIVITY,
        outcome=outcome,
        action=action,
        initiator=initiator,
        target=target,
        observer=resource.Resource(typeURI=taxonomy.SERVICE_SECURITY))

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
            LOG.exception(_LE(
                'Failed to send %(action)s %(event_type)s notification'),
                {'action': action, 'event_type': event_type})


emit_event = CadfNotificationWrapper


role_assignment = CadfRoleAssignmentNotificationWrapper
