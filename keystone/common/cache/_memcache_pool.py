# Copyright 2014 Mirantis Inc
# All Rights Reserved.
#
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

"""Thread-safe connection pool for python-memcached."""

# NOTE(yorik-sar): this file is copied between keystone and keystonemiddleware
# and should be kept in sync until we can use external library for this.

import collections
import contextlib
import itertools
import logging
import threading
import time

import memcache
from oslo_log import log
from six.moves import queue, zip

from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)


class _MemcacheClient(memcache.Client):
    """Thread global memcache client

    As client is inherited from threading.local we have to restore object
    methods overloaded by threading.local so we can reuse clients in
    different threads
    """
    __delattr__ = object.__delattr__
    __getattribute__ = object.__getattribute__
    __new__ = object.__new__
    __setattr__ = object.__setattr__

    def __del__(self):
        pass


_PoolItem = collections.namedtuple('_PoolItem', ['ttl', 'connection'])


class ConnectionPool(queue.Queue):
    """Base connection pool class

    This class implements the basic connection pool logic as an abstract base
    class.
    """
    def __init__(self, maxsize, unused_timeout, conn_get_timeout=None):
        """Initialize the connection pool.

        :param maxsize: maximum number of client connections for the pool
        :type maxsize: int
        :param unused_timeout: idle time to live for unused clients (in
                               seconds). If a client connection object has been
                               in the pool and idle for longer than the
                               unused_timeout, it will be reaped. This is to
                               ensure resources are released as utilization
                               goes down.
        :type unused_timeout: int
        :param conn_get_timeout: maximum time in seconds to wait for a
                                 connection. If set to `None` timeout is
                                 indefinite.
        :type conn_get_timeout: int
        """
        # super() cannot be used here because Queue in stdlib is an
        # old-style class
        queue.Queue.__init__(self, maxsize)
        self._unused_timeout = unused_timeout
        self._connection_get_timeout = conn_get_timeout
        self._acquired = 0

    def _create_connection(self):
        """Returns a connection instance.

        This is called when the pool needs another instance created.

        :returns: a new connection instance

        """
        raise NotImplementedError

    def _destroy_connection(self, conn):
        """Destroy and cleanup a connection instance.

        This is called when the pool wishes to get rid of an existing
        connection. This is the opportunity for a subclass to free up
        resources and cleaup after itself.

        :param conn: the connection object to destroy

        """
        raise NotImplementedError

    def _debug_logger(self, msg, *args, **kwargs):
        if LOG.isEnabledFor(logging.DEBUG):
            thread_id = threading.current_thread().ident
            args = (id(self), thread_id) + args
            prefix = 'Memcached pool %s, thread %s: '
            LOG.debug(prefix + msg, *args, **kwargs)

    @contextlib.contextmanager
    def acquire(self):
        self._debug_logger('Acquiring connection')
        try:
            conn = self.get(timeout=self._connection_get_timeout)
        except queue.Empty:
            raise exception.UnexpectedError(
                _('Unable to get a connection from pool id %(id)s after '
                  '%(seconds)s seconds.') %
                {'id': id(self), 'seconds': self._connection_get_timeout})
        self._debug_logger('Acquired connection %s', id(conn))
        try:
            yield conn
        finally:
            self._debug_logger('Releasing connection %s', id(conn))
            self._drop_expired_connections()
            try:
                # super() cannot be used here because Queue in stdlib is an
                # old-style class
                queue.Queue.put(self, conn, block=False)
            except queue.Full:
                self._debug_logger('Reaping exceeding connection %s', id(conn))
                self._destroy_connection(conn)

    def _qsize(self):
        if self.maxsize:
            return self.maxsize - self._acquired
        else:
            # A value indicating there is always a free connection
            # if maxsize is None or 0
            return 1

    # NOTE(dstanek): stdlib and eventlet Queue implementations
    # have different names for the qsize method. This ensures
    # that we override both of them.
    if not hasattr(queue.Queue, '_qsize'):
        qsize = _qsize

    def _get(self):
        if self.queue:
            conn = self.queue.pop().connection
        else:
            conn = self._create_connection()
        self._acquired += 1
        return conn

    def _drop_expired_connections(self):
        """Drop all expired connections from the right end of the queue."""
        now = time.time()
        while self.queue and self.queue[0].ttl < now:
            conn = self.queue.popleft().connection
            self._debug_logger('Reaping connection %s', id(conn))
            self._destroy_connection(conn)

    def _put(self, conn):
        self.queue.append(_PoolItem(
            ttl=time.time() + self._unused_timeout,
            connection=conn,
        ))
        self._acquired -= 1


class MemcacheClientPool(ConnectionPool):
    def __init__(self, urls, arguments, **kwargs):
        # super() cannot be used here because Queue in stdlib is an
        # old-style class
        ConnectionPool.__init__(self, **kwargs)
        self.urls = urls
        self._arguments = arguments
        # NOTE(morganfainberg): The host objects expect an int for the
        # deaduntil value. Initialize this at 0 for each host with 0 indicating
        # the host is not dead.
        self._hosts_deaduntil = [0] * len(urls)

    def _create_connection(self):
        return _MemcacheClient(self.urls, **self._arguments)

    def _destroy_connection(self, conn):
        conn.disconnect_all()

    def _get(self):
        # super() cannot be used here because Queue in stdlib is an
        # old-style class
        conn = ConnectionPool._get(self)
        try:
            # Propagate host state known to us to this client's list
            now = time.time()
            for deaduntil, host in zip(self._hosts_deaduntil, conn.servers):
                if deaduntil > now and host.deaduntil <= now:
                    host.mark_dead('propagating death mark from the pool')
                host.deaduntil = deaduntil
        except Exception:
            # We need to be sure that connection doesn't leak from the pool.
            # This code runs before we enter context manager's try-finally
            # block, so we need to explicitly release it here.
            # super() cannot be used here because Queue in stdlib is an
            # old-style class
            ConnectionPool._put(self, conn)
            raise
        return conn

    def _put(self, conn):
        try:
            # If this client found that one of the hosts is dead, mark it as
            # such in our internal list
            now = time.time()
            for i, host in zip(itertools.count(), conn.servers):
                deaduntil = self._hosts_deaduntil[i]
                # Do nothing if we already know this host is dead
                if deaduntil <= now:
                    if host.deaduntil > now:
                        self._hosts_deaduntil[i] = host.deaduntil
                        self._debug_logger(
                            'Marked host %s dead until %s',
                            self.urls[i], host.deaduntil)
                    else:
                        self._hosts_deaduntil[i] = 0
            # If all hosts are dead we should forget that they're dead. This
            # way we won't get completely shut off until dead_retry seconds
            # pass, but will be checking servers as frequent as we can (over
            # way smaller socket_timeout)
            if all(deaduntil > now for deaduntil in self._hosts_deaduntil):
                self._debug_logger('All hosts are dead. Marking them as live.')
                self._hosts_deaduntil[:] = [0] * len(self._hosts_deaduntil)
        finally:
            # super() cannot be used here because Queue in stdlib is an
            # old-style class
            ConnectionPool._put(self, conn)
