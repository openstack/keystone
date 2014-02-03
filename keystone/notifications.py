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

import logging
import socket

from oslo.config import cfg
from oslo import messaging
import pycadf
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import resource

from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import log

notifier_opts = [
    cfg.StrOpt('default_publisher_id',
               default=None,
               help='Default publisher_id for outgoing notifications'),
]

LOG = log.getLogger(__name__)
# NOTE(gyee): actions that can be notified. One must update this list whenever
# a new action is supported.
ACTIONS = frozenset(['created', 'deleted', 'disabled', 'updated'])
# resource types that can be notified
SUBSCRIBERS = {}
_notifier = None


CONF = cfg.CONF
CONF.register_opts(notifier_opts)


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
                 resource_id_arg_index=1):
        self.operation = operation
        self.resource_type = resource_type
        self.public = public
        self.resource_id_arg_index = resource_id_arg_index

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            """Send a notification if the wrapped callable is successful."""
            try:
                result = f(*args, **kwargs)
            except Exception:
                raise
            else:
                resource_id = args[self.resource_id_arg_index]
                _send_notification(
                    self.operation,
                    self.resource_type,
                    resource_id,
                    public=self.public)
            return result

        return wrapper


def created(*args, **kwargs):
    """Decorator to send notifications for ``Manager.create_*`` methods."""
    return ManagerNotificationWrapper('created', *args, **kwargs)


def updated(*args, **kwargs):
    """Decorator to send notifications for ``Manager.update_*`` methods."""
    return ManagerNotificationWrapper('updated', *args, **kwargs)


def disabled(*args, **kwargs):
    """Decorator to send notifications when an object is disabled."""
    return ManagerNotificationWrapper('disabled', *args, **kwargs)


def deleted(*args, **kwargs):
    """Decorator to send notifications for ``Manager.delete_*`` methods."""
    return ManagerNotificationWrapper('deleted', *args, **kwargs)


def _get_callback_info(callback):
    if getattr(callback, 'im_class', None):
        return [getattr(callback, '__module__', None),
                callback.im_class.__name__,
                callback.__name__]
    else:
        return [getattr(callback, '__module__', None), callback.__name__]


def register_event_callback(event, resource_type, callbacks):
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
        SUBSCRIBERS.setdefault(event, {}).setdefault(resource_type, set())
        SUBSCRIBERS[event][resource_type].add(callback)

        if LOG.logger.getEffectiveLevel() <= logging.INFO:
            # Do this only if its going to appear in the logs.
            msg = _('Callback: `%(callback)s` subscribed to event '
                    '`%(event)s`.')
            callback_info = _get_callback_info(callback)
            callback_str = '.'.join(i for i in callback_info if i is not None)
            event_str = '.'.join(['identity', resource_type, event])
            LOG.info(msg, {'callback': callback_str, 'event': event_str})


def notify_event_callbacks(service, resource_type, operation, payload):
    """Sends a notification to registered extensions."""
    if operation in SUBSCRIBERS:
        if resource_type in SUBSCRIBERS[operation]:
            for cb in SUBSCRIBERS[operation][resource_type]:
                subst_dict = {'cb_name': cb.__name__,
                              'service': service,
                              'resource_type': resource_type,
                              'operation': operation,
                              'payload': payload}
                LOG.debug(_('Invoking callback %(cb_name)s for event '
                          '%(service)s %(resource_type)s %(operation)s for'
                          '%(payload)s'),
                          subst_dict)
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
            transport = messaging.get_transport(CONF)
            _notifier = messaging.Notifier(transport, "identity.%s" % host)
        except Exception:
            LOG.exception("Failed to construct notifier")
            _notifier = False

    return _notifier


def _reset_notifier():
    global _notifier
    _notifier = None


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
    context = {}
    payload = {'resource_info': resource_id}
    service = 'identity'
    event_type = '%(service)s.%(resource_type)s.%(operation)s' % {
        'service': service,
        'resource_type': resource_type,
        'operation': operation}

    notify_event_callbacks(service, resource_type, operation, payload)

    if public:
        notifier = _get_notifier()
        if notifier:
            try:
                notifier.info(context, event_type, payload)
            except Exception:
                LOG.exception(_(
                    'Failed to send %(res_id)s %(event_type)s notification'),
                    {'res_id': resource_id, 'event_type': event_type})


class CadfNotificationWrapper(object):
    """Send CADF event notifications for various methods.

    Sends CADF notifications for events such as whether an authentication was
    successful or not.

    """

    def __init__(self, action):
        self.action = action

    def __call__(self, f):
        def wrapper(wrapped_self, context, user_id, *args, **kwargs):
            """Always send a notification."""

            remote_addr = None
            http_user_agent = None
            environment = context.get('environment')

            if environment:
                remote_addr = environment.get('REMOTE_ADDR')
                http_user_agent = environment.get('HTTP_USER_AGENT')

            host = pycadf.host.Host(address=remote_addr, agent=http_user_agent)
            initiator = resource.Resource(typeURI=taxonomy.ACCOUNT_USER,
                                          name=user_id, host=host)

            _send_audit_notification(self.action, initiator,
                                     taxonomy.OUTCOME_PENDING)
            try:
                result = f(wrapped_self, context, user_id, *args, **kwargs)
            except Exception:
                # For authentication failure send a cadf event as well
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_FAILURE)
                raise
            else:
                _send_audit_notification(self.action, initiator,
                                         taxonomy.OUTCOME_SUCCESS)
                return result

        return wrapper


def _send_audit_notification(action, initiator, outcome):
    """Send CADF notification to inform observers about the affected resource.

    This method logs an exception when sending the notification fails.

    :param action: CADF action being audited (e.g., 'authenticate')
    :param initiator: CADF resource representing the initiator
    :param outcome: The CADF outcome (taxonomy.OUTCOME_PENDING,
        taxonomy.OUTCOME_SUCCESS, taxonomy.OUTCOME_FAILURE)

    """

    event = eventfactory.EventFactory().new_event(
        eventType=cadftype.EVENTTYPE_ACTIVITY,
        outcome=outcome,
        action=action,
        initiator=initiator,
        target=resource.Resource(typeURI=taxonomy.ACCOUNT_USER),
        observer=resource.Resource(typeURI='service/security'))

    context = {}
    payload = event.as_dict()
    LOG.debug(_('CADF Event: %s'), payload)
    service = 'identity'
    event_type = '%(service)s.%(action)s' % {'service': service,
                                             'action': action}

    notifier = _get_notifier()

    if notifier:
        try:
            notifier.info(context, event_type, payload)
        except Exception:
            # diaper defense: any exception that occurs while emitting the
            # notification should not interfere with the API request
            LOG.exception(_(
                'Failed to send %(action)s %(event_type)s notification'),
                {'action': action, 'event_type': event_type})


emit_event = CadfNotificationWrapper
