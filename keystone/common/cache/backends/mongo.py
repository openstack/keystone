# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

import abc
import datetime

from dogpile.cache import api
from dogpile.cache import util as dp_util
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import timeutils
import six

from keystone import exception
from keystone.i18n import _, _LW


NO_VALUE = api.NO_VALUE
LOG = log.getLogger(__name__)


class MongoCacheBackend(api.CacheBackend):
    """A MongoDB based caching backend implementing dogpile backend APIs.

    Arguments accepted in the arguments dictionary:

    :param db_hosts: string (required), hostname or IP address of the
        MongoDB server instance. This can be a single MongoDB connection URI,
        or a list of MongoDB connection URIs.

    :param db_name: string (required), the name of the database to be used.

    :param cache_collection: string (required), the name of collection to store
        cached data.
        *Note:* Different collection name can be provided if there is need to
        create separate container (i.e. collection) for cache data. So region
        configuration is done per collection.

    Following are optional parameters for MongoDB backend configuration,

    :param username: string, the name of the user to authenticate.

    :param password: string, the password of the user to authenticate.

    :param max_pool_size: integer, the maximum number of connections that the
        pool will open simultaneously. By default the pool size is 10.

    :param w: integer, write acknowledgement for MongoDB client

        If not provided, then no default is set on MongoDB and then write
        acknowledgement behavior occurs as per MongoDB default. This parameter
        name is same as what is used in MongoDB docs. This value is specified
        at collection level so its applicable to `cache_collection` db write
        operations.

        If this is a replica set, write operations will block until they have
        been replicated to the specified number or tagged set  of servers.
        Setting w=0 disables write acknowledgement and all other write concern
        options.

    :param read_preference: string, the read preference mode for MongoDB client
        Expected value is ``primary``, ``primaryPreferred``, ``secondary``,
        ``secondaryPreferred``, or ``nearest``. This read_preference is
        specified at collection level so its applicable to `cache_collection`
        db read operations.

    :param use_replica: boolean, flag to indicate if replica client to be
        used. Default is `False`. `replicaset_name` value is required if
        `True`.

    :param replicaset_name: string, name of replica set.
        Becomes required if `use_replica` is `True`

    :param son_manipulator: string, name of class with module name which
        implements MongoDB SONManipulator.
        Default manipulator used is :class:`.BaseTransform`.

        This manipulator is added per database. In multiple cache
        configurations, the manipulator name should be same if same
        database name ``db_name`` is used in those configurations.

        SONManipulator is used to manipulate custom data types as they are
        saved or retrieved from MongoDB. Custom impl is only needed if cached
        data is custom class and needs transformations when saving or reading
        from db. If dogpile cached value contains built-in data types, then
        BaseTransform class is sufficient as it already handles dogpile
        CachedValue class transformation.

    :param mongo_ttl_seconds: integer, interval in seconds to indicate maximum
        time-to-live value.
        If value is greater than 0, then its assumed that cache_collection
        needs to be TTL type (has index at 'doc_date' field).
        By default, the value is -1 and its disabled.
        Reference: <http://docs.mongodb.org/manual/tutorial/expire-data/>

        .. NOTE::

            This parameter is different from Dogpile own
            expiration_time, which is the number of seconds after which Dogpile
            will consider the value to be expired. When Dogpile considers a
            value to be expired, it continues to use the value until generation
            of a new value is complete, when using CacheRegion.get_or_create().
            Therefore, if you are setting `mongo_ttl_seconds`, you will want to
            make sure it is greater than expiration_time by at least enough
            seconds for new values to be generated, else the value would not
            be available during a regeneration, forcing all threads to wait for
            a regeneration each time a value expires.

    :param ssl: boolean, If True, create the connection to the server
        using SSL. Default is `False`. Client SSL connection parameters depends
        on server side SSL setup. For further reference on SSL configuration:
        <http://docs.mongodb.org/manual/tutorial/configure-ssl/>

    :param ssl_keyfile: string, the private keyfile used to identify the
        local connection against mongod. If included with the certfile then
        only the `ssl_certfile` is needed. Used only when `ssl` is `True`.

    :param ssl_certfile: string, the certificate file used to identify the
        local connection against mongod. Used only when `ssl` is `True`.

    :param ssl_ca_certs: string, the ca_certs file contains a set of
        concatenated 'certification authority' certificates, which are used to
        validate certificates passed from the other end of the connection.
        Used only when `ssl` is `True`.

    :param ssl_cert_reqs: string, the parameter cert_reqs specifies whether
        a certificate is required from the other side of the connection, and
        whether it will be validated if provided. It must be one of the three
        values ``ssl.CERT_NONE`` (certificates ignored), ``ssl.CERT_OPTIONAL``
        (not required, but validated if provided), or
        ``ssl.CERT_REQUIRED`` (required and validated). If the value of this
        parameter is not ``ssl.CERT_NONE``, then the ssl_ca_certs parameter
        must point to a file of CA certificates. Used only when `ssl`
        is `True`.

    Rest of arguments are passed to mongo calls for read, write and remove.
    So related options can be specified to pass to these operations.

    Further details of various supported arguments can be referred from
    <http://api.mongodb.org/python/current/api/pymongo/>

    """

    def __init__(self, arguments):
        self.api = MongoApi(arguments)

    @dp_util.memoized_property
    def client(self):
        """Initializes MongoDB connection and collection defaults.

        This initialization is done only once and performed as part of lazy
        inclusion of MongoDB dependency i.e. add imports only if related
        backend is used.

        :return: :class:`.MongoApi` instance
        """
        self.api.get_cache_collection()
        return self.api

    def get(self, key):
        value = self.client.get(key)
        if value is None:
            return NO_VALUE
        else:
            return value

    def get_multi(self, keys):
        values = self.client.get_multi(keys)
        return [
            NO_VALUE if key not in values
            else values[key] for key in keys
        ]

    def set(self, key, value):
        self.client.set(key, value)

    def set_multi(self, mapping):
        self.client.set_multi(mapping)

    def delete(self, key):
        self.client.delete(key)

    def delete_multi(self, keys):
        self.client.delete_multi(keys)


class MongoApi(object):
    """Class handling MongoDB specific functionality.

    This class uses PyMongo APIs internally to create database connection
    with configured pool size, ensures unique index on key, does database
    authentication and ensure TTL collection index if configured so.
    This class also serves as handle to cache collection for dogpile cache
    APIs.

    In a single deployment, multiple cache configuration can be defined. In
    that case of multiple cache collections usage, db client connection pool
    is shared when cache collections are within same database.
    """

    # class level attributes for re-use of db client connection and collection
    _DB = {}  # dict of db_name: db connection reference
    _MONGO_COLLS = {}  # dict of cache_collection : db collection reference

    def __init__(self, arguments):
        self._init_args(arguments)
        self._data_manipulator = None

    def _init_args(self, arguments):
        """Helper logic for collecting and parsing MongoDB specific arguments.

        The arguments passed in are separated out in connection specific
        setting and rest of arguments are passed to create/update/delete
        db operations.
        """
        self.conn_kwargs = {}  # connection specific arguments

        self.hosts = arguments.pop('db_hosts', None)
        if self.hosts is None:
            msg = _('db_hosts value is required')
            raise exception.ValidationError(message=msg)

        self.db_name = arguments.pop('db_name', None)
        if self.db_name is None:
            msg = _('database db_name is required')
            raise exception.ValidationError(message=msg)

        self.cache_collection = arguments.pop('cache_collection', None)
        if self.cache_collection is None:
            msg = _('cache_collection name is required')
            raise exception.ValidationError(message=msg)

        self.username = arguments.pop('username', None)
        self.password = arguments.pop('password', None)
        self.max_pool_size = arguments.pop('max_pool_size', 10)

        self.w = arguments.pop('w', -1)
        try:
            self.w = int(self.w)
        except ValueError:
            msg = _('integer value expected for w (write concern attribute)')
            raise exception.ValidationError(message=msg)

        self.read_preference = arguments.pop('read_preference', None)

        self.use_replica = arguments.pop('use_replica', False)
        if self.use_replica:
            if arguments.get('replicaset_name') is None:
                msg = _('replicaset_name required when use_replica is True')
                raise exception.ValidationError(message=msg)
            self.replicaset_name = arguments.get('replicaset_name')

        self.son_manipulator = arguments.pop('son_manipulator', None)

        # set if mongo collection needs to be TTL type.
        # This needs to be max ttl for any cache entry.
        # By default, -1 means don't use TTL collection.
        # With ttl set, it creates related index and have doc_date field with
        # needed expiration interval
        self.ttl_seconds = arguments.pop('mongo_ttl_seconds', -1)
        try:
            self.ttl_seconds = int(self.ttl_seconds)
        except ValueError:
            msg = _('integer value expected for mongo_ttl_seconds')
            raise exception.ValidationError(message=msg)

        self.conn_kwargs['ssl'] = arguments.pop('ssl', False)
        if self.conn_kwargs['ssl']:
            ssl_keyfile = arguments.pop('ssl_keyfile', None)
            ssl_certfile = arguments.pop('ssl_certfile', None)
            ssl_ca_certs = arguments.pop('ssl_ca_certs', None)
            ssl_cert_reqs = arguments.pop('ssl_cert_reqs', None)
            if ssl_keyfile:
                self.conn_kwargs['ssl_keyfile'] = ssl_keyfile
            if ssl_certfile:
                self.conn_kwargs['ssl_certfile'] = ssl_certfile
            if ssl_ca_certs:
                self.conn_kwargs['ssl_ca_certs'] = ssl_ca_certs
            if ssl_cert_reqs:
                self.conn_kwargs['ssl_cert_reqs'] = (
                    self._ssl_cert_req_type(ssl_cert_reqs))

        # rest of arguments are passed to mongo crud calls
        self.meth_kwargs = arguments

    def _ssl_cert_req_type(self, req_type):
        try:
            import ssl
        except ImportError:
            raise exception.ValidationError(_('no ssl support available'))
        req_type = req_type.upper()
        try:
            return {
                'NONE': ssl.CERT_NONE,
                'OPTIONAL': ssl.CERT_OPTIONAL,
                'REQUIRED': ssl.CERT_REQUIRED
            }[req_type]
        except KeyError:
            msg = _('Invalid ssl_cert_reqs value of %s, must be one of '
                    '"NONE", "OPTIONAL", "REQUIRED"') % (req_type)
            raise exception.ValidationError(message=msg)

    def _get_db(self):
        # defer imports until backend is used
        global pymongo
        import pymongo
        if self.use_replica:
            connection = pymongo.MongoReplicaSetClient(
                host=self.hosts, replicaSet=self.replicaset_name,
                max_pool_size=self.max_pool_size, **self.conn_kwargs)
        else:  # used for standalone node or mongos in sharded setup
            connection = pymongo.MongoClient(
                host=self.hosts, max_pool_size=self.max_pool_size,
                **self.conn_kwargs)

        database = getattr(connection, self.db_name)

        self._assign_data_mainpulator()
        database.add_son_manipulator(self._data_manipulator)
        if self.username and self.password:
            database.authenticate(self.username, self.password)
        return database

    def _assign_data_mainpulator(self):
        if self._data_manipulator is None:
            if self.son_manipulator:
                self._data_manipulator = importutils.import_object(
                    self.son_manipulator)
            else:
                self._data_manipulator = BaseTransform()

    def _get_doc_date(self):
        if self.ttl_seconds > 0:
            expire_delta = datetime.timedelta(seconds=self.ttl_seconds)
            doc_date = timeutils.utcnow() + expire_delta
        else:
            doc_date = timeutils.utcnow()
        return doc_date

    def get_cache_collection(self):
        if self.cache_collection not in self._MONGO_COLLS:
            global pymongo
            import pymongo
            # re-use db client connection if already defined as part of
            # earlier dogpile cache configuration
            if self.db_name not in self._DB:
                self._DB[self.db_name] = self._get_db()
            coll = getattr(self._DB[self.db_name], self.cache_collection)

            self._assign_data_mainpulator()
            if self.read_preference:
                # pymongo 3.0 renamed mongos_enum to read_pref_mode_from_name
                f = getattr(pymongo.read_preferences,
                            'read_pref_mode_from_name', None)
                if not f:
                    f = pymongo.read_preferences.mongos_enum
                self.read_preference = f(self.read_preference)
                coll.read_preference = self.read_preference
            if self.w > -1:
                coll.write_concern['w'] = self.w
            if self.ttl_seconds > 0:
                kwargs = {'expireAfterSeconds': self.ttl_seconds}
                coll.ensure_index('doc_date', cache_for=5, **kwargs)
            else:
                self._validate_ttl_index(coll, self.cache_collection,
                                         self.ttl_seconds)
            self._MONGO_COLLS[self.cache_collection] = coll

        return self._MONGO_COLLS[self.cache_collection]

    def _get_cache_entry(self, key, value, meta, doc_date):
        """MongoDB cache data representation.

        Storing cache key as ``_id`` field as MongoDB by default creates
        unique index on this field. So no need to create separate field and
        index for storing cache key. Cache data has additional ``doc_date``
        field for MongoDB TTL collection support.
        """
        return dict(_id=key, value=value, meta=meta, doc_date=doc_date)

    def _validate_ttl_index(self, collection, coll_name, ttl_seconds):
        """Checks if existing TTL index is removed on a collection.

        This logs warning when existing collection has TTL index defined and
        new cache configuration tries to disable index with
        ``mongo_ttl_seconds < 0``. In that case, existing index needs
        to be addressed first to make new configuration effective.
        Refer to MongoDB documentation around TTL index for further details.
        """
        indexes = collection.index_information()
        for indx_name, index_data in indexes.items():
            if all(k in index_data for k in ('key', 'expireAfterSeconds')):
                existing_value = index_data['expireAfterSeconds']
                fld_present = 'doc_date' in index_data['key'][0]
                if fld_present and existing_value > -1 and ttl_seconds < 1:
                    msg = _LW('TTL index already exists on db collection '
                              '<%(c_name)s>, remove index <%(indx_name)s> '
                              'first to make updated mongo_ttl_seconds value '
                              'to be  effective')
                    LOG.warn(msg, {'c_name': coll_name,
                                   'indx_name': indx_name})

    def get(self, key):
        critieria = {'_id': key}
        result = self.get_cache_collection().find_one(spec_or_id=critieria,
                                                      **self.meth_kwargs)
        if result:
            return result['value']
        else:
            return None

    def get_multi(self, keys):
        db_results = self._get_results_as_dict(keys)
        return {doc['_id']: doc['value'] for doc in six.itervalues(db_results)}

    def _get_results_as_dict(self, keys):
        critieria = {'_id': {'$in': keys}}
        db_results = self.get_cache_collection().find(spec=critieria,
                                                      **self.meth_kwargs)
        return {doc['_id']: doc for doc in db_results}

    def set(self, key, value):
        doc_date = self._get_doc_date()
        ref = self._get_cache_entry(key, value.payload, value.metadata,
                                    doc_date)
        spec = {'_id': key}
        # find and modify does not have manipulator support
        # so need to do conversion as part of input document
        ref = self._data_manipulator.transform_incoming(ref, self)
        self.get_cache_collection().find_and_modify(spec, ref, upsert=True,
                                                    **self.meth_kwargs)

    def set_multi(self, mapping):
        """Insert multiple documents specified as key, value pairs.

        In this case, multiple documents can be added via insert provided they
        do not exist.
        Update of multiple existing documents is done one by one
        """
        doc_date = self._get_doc_date()
        insert_refs = []
        update_refs = []
        existing_docs = self._get_results_as_dict(list(mapping.keys()))
        for key, value in mapping.items():
            ref = self._get_cache_entry(key, value.payload, value.metadata,
                                        doc_date)
            if key in existing_docs:
                ref['_id'] = existing_docs[key]['_id']
                update_refs.append(ref)
            else:
                insert_refs.append(ref)
        if insert_refs:
            self.get_cache_collection().insert(insert_refs, manipulate=True,
                                               **self.meth_kwargs)
        for upd_doc in update_refs:
            self.get_cache_collection().save(upd_doc, manipulate=True,
                                             **self.meth_kwargs)

    def delete(self, key):
        critieria = {'_id': key}
        self.get_cache_collection().remove(spec_or_id=critieria,
                                           **self.meth_kwargs)

    def delete_multi(self, keys):
        critieria = {'_id': {'$in': keys}}
        self.get_cache_collection().remove(spec_or_id=critieria,
                                           **self.meth_kwargs)


@six.add_metaclass(abc.ABCMeta)
class AbstractManipulator(object):
    """Abstract class with methods which need to be implemented for custom
    manipulation.

    Adding this as a base class for :class:`.BaseTransform` instead of adding
    import dependency of pymongo specific class i.e.
    `pymongo.son_manipulator.SONManipulator` and using that as base class.
    This is done to avoid pymongo dependency if MongoDB backend is not used.
    """
    @abc.abstractmethod
    def transform_incoming(self, son, collection):
        """Used while saving data to MongoDB.

        :param son: the SON object to be inserted into the database
        :param collection: the collection the object is being inserted into

        :returns: transformed SON object

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def transform_outgoing(self, son, collection):
        """Used while reading data from MongoDB.

        :param son: the SON object being retrieved from the database
        :param collection: the collection this object was stored in

        :returns: transformed SON object
        """
        raise exception.NotImplemented()  # pragma: no cover

    def will_copy(self):
        """Will this SON manipulator make a copy of the incoming document?

        Derived classes that do need to make a copy should override this
        method, returning `True` instead of `False`.

        :returns: boolean
        """
        return False


class BaseTransform(AbstractManipulator):
    """Base transformation class to store and read dogpile cached data
    from MongoDB.

    This is needed as dogpile internally stores data as a custom class
    i.e. dogpile.cache.api.CachedValue

    Note: Custom manipulator needs to always override ``transform_incoming``
    and ``transform_outgoing`` methods. MongoDB manipulator logic specifically
    checks that overridden method in instance and its super are different.
    """

    def transform_incoming(self, son, collection):
        """Used while saving data to MongoDB."""
        for (key, value) in list(son.items()):
            if isinstance(value, api.CachedValue):
                son[key] = value.payload  # key is 'value' field here
                son['meta'] = value.metadata
            elif isinstance(value, dict):  # Make sure we recurse into sub-docs
                son[key] = self.transform_incoming(value, collection)
        return son

    def transform_outgoing(self, son, collection):
        """Used while reading data from MongoDB."""
        metadata = None
        # make sure its top level dictionary with all expected fields names
        # present
        if isinstance(son, dict) and all(k in son for k in
                                         ('_id', 'value', 'meta', 'doc_date')):
            payload = son.pop('value', None)
            metadata = son.pop('meta', None)
        for (key, value) in list(son.items()):
            if isinstance(value, dict):
                son[key] = self.transform_outgoing(value, collection)
        if metadata is not None:
            son['value'] = api.CachedValue(payload, metadata)
        return son
