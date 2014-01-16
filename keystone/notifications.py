# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from keystone.openstack.common import log
from keystone.openstack.common.notifier import api as notifier_api


LOG = log.getLogger(__name__)
# NOTE(gyee): actions that can be notified. One must update this list whenever
# a new action is supported.
ACTIONS = frozenset(['created', 'deleted', 'updated'])
# resource types that can be notified
RESOURCE_TYPES = set()
SUBSCRIBERS = {}


class ManagerNotificationWrapper(object):
    """Send event notifications for ``Manager`` methods.

    Sends a notification if the wrapped Manager method does not raise an
    ``Exception`` (such as ``keystone.exception.NotFound``).

    :param resource_type: type of resource being affected
    :param host: host of the resource (optional)
    """
    def __init__(self, operation, resource_type, host=None):
        self.operation = operation
        self.resource_type = resource_type
        RESOURCE_TYPES.add(resource_type)
        self.host = host

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            """Send a notification if the wrapped callable is successful."""
            try:
                result = f(*args, **kwargs)
            except Exception:
                raise
            else:
                _send_notification(
                    self.operation,
                    self.resource_type,
                    args[1],  # f(self, resource_id, ...)
                    self.host)
            return result

        return wrapper


def created(*args, **kwargs):
    """Decorator to send notifications for ``Manager.create_*`` methods."""
    return ManagerNotificationWrapper('created', *args, **kwargs)


def updated(*args, **kwargs):
    """Decorator to send notifications for ``Manager.update_*`` methods."""
    return ManagerNotificationWrapper('updated', *args, **kwargs)


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
    if resource_type not in RESOURCE_TYPES:
        raise ValueError(_('%(resource_type)s is not a valid notification '
                           'resource, must be one of: %(types)s') %
                         {'resource_type': resource_type,
                          'types': ', '.join(RESOURCE_TYPES)})

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
            callback_str = '.'.join(
                filter(lambda i: i is not None, callback_info))
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


def _send_notification(operation, resource_type, resource_id, host=None):
    """Send notification to inform observers about the affected resource.

    This method doesn't raise an exception when sending the notification fails.

    :param operation: operation being performed (created, updated, or deleted)
    :param resource_type: type of resource being operated on
    :param resource_id: ID of resource being operated on
    :param host: resource host
    """
    context = {}
    payload = {'resource_info': resource_id}
    service = 'identity'
    publisher_id = notifier_api.publisher_id(service, host=host)
    event_type = '%(service)s.%(resource_type)s.%(operation)s' % {
        'service': service,
        'resource_type': resource_type,
        'operation': operation}

    notify_event_callbacks(service, resource_type, operation, payload)

    try:
        notifier_api.notify(
            context, publisher_id, event_type, notifier_api.INFO, payload)
    except Exception:
        LOG.exception(
            _('Failed to send %(res_id)s %(event_type)s notification'),
            {'res_id': resource_id, 'event_type': event_type})
