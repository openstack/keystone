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

import collections
import copy
import functools
import uuid

from dogpile.cache import api
from dogpile.cache import region as dp_region
import six
from six.moves import range

from keystone.common.cache.backends import mongo
from keystone import exception
from keystone.tests import unit


# Mock database structure sample where 'ks_cache' is database and
# 'cache' is collection. Dogpile CachedValue data is divided in two
# fields `value` (CachedValue.payload) and `meta` (CachedValue.metadata)
ks_cache = {
    "cache": [
        {
            "value": {
                "serviceType": "identity",
                "allVersionsUrl": "https://dummyUrl",
                "dateLastModified": "ISODDate(2014-02-08T18:39:13.237Z)",
                "serviceName": "Identity",
                "enabled": "True"
            },
            "meta": {
                "v": 1,
                "ct": 1392371422.015121
            },
            "doc_date": "ISODate('2014-02-14T09:50:22.015Z')",
            "_id": "8251dc95f63842719c077072f1047ddf"
        },
        {
            "value": "dummyValueX",
            "meta": {
                "v": 1,
                "ct": 1392371422.014058
            },
            "doc_date": "ISODate('2014-02-14T09:50:22.014Z')",
            "_id": "66730b9534d146f0804d23729ad35436"
        }
    ]
}


COLLECTIONS = {}
SON_MANIPULATOR = None


class MockCursor(object):

    def __init__(self, collection, dataset_factory):
        super(MockCursor, self).__init__()
        self.collection = collection
        self._factory = dataset_factory
        self._dataset = self._factory()
        self._limit = None
        self._skip = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._skip:
            for _ in range(self._skip):
                next(self._dataset)
            self._skip = None
        if self._limit is not None and self._limit <= 0:
            raise StopIteration()
        if self._limit is not None:
            self._limit -= 1
        return next(self._dataset)

    next = __next__

    def __getitem__(self, index):
        arr = [x for x in self._dataset]
        self._dataset = iter(arr)
        return arr[index]


class MockCollection(object):

    def __init__(self, db, name):
        super(MockCollection, self).__init__()
        self.name = name
        self._collection_database = db
        self._documents = {}
        self.write_concern = {}

    def __getattr__(self, name):
        if name == 'database':
            return self._collection_database

    def ensure_index(self, key_or_list, *args, **kwargs):
        pass

    def index_information(self):
        return {}

    def find_one(self, spec_or_id=None, *args, **kwargs):
        if spec_or_id is None:
            spec_or_id = {}
        if not isinstance(spec_or_id, collections.Mapping):
            spec_or_id = {'_id': spec_or_id}

        try:
            return next(self.find(spec_or_id, *args, **kwargs))
        except StopIteration:
            return None

    def find(self, spec=None, *args, **kwargs):
        return MockCursor(self, functools.partial(self._get_dataset, spec))

    def _get_dataset(self, spec):
        dataset = (self._copy_doc(document, dict) for document in
                   self._iter_documents(spec))
        return dataset

    def _iter_documents(self, spec=None):
        return (SON_MANIPULATOR.transform_outgoing(document, self) for
                document in six.itervalues(self._documents)
                if self._apply_filter(document, spec))

    def _apply_filter(self, document, query):
        for key, search in query.items():
            doc_val = document.get(key)
            if isinstance(search, dict):
                op_dict = {'$in': lambda dv, sv: dv in sv}
                is_match = all(
                    op_str in op_dict and op_dict[op_str](doc_val, search_val)
                    for op_str, search_val in search.items()
                )
            else:
                is_match = doc_val == search

        return is_match

    def _copy_doc(self, obj, container):
        if isinstance(obj, list):
            new = []
            for item in obj:
                new.append(self._copy_doc(item, container))
            return new
        if isinstance(obj, dict):
            new = container()
            for key, value in list(obj.items()):
                new[key] = self._copy_doc(value, container)
            return new
        else:
            return copy.copy(obj)

    def insert(self, data, manipulate=True, **kwargs):
        if isinstance(data, list):
            return [self._insert(element) for element in data]
        return self._insert(data)

    def save(self, data, manipulate=True, **kwargs):
        return self._insert(data)

    def _insert(self, data):
        if '_id' not in data:
            data['_id'] = uuid.uuid4().hex
        object_id = data['_id']
        self._documents[object_id] = self._internalize_dict(data)
        return object_id

    def find_and_modify(self, spec, document, upsert=False, **kwargs):
        self.update(spec, document, upsert, **kwargs)

    def update(self, spec, document, upsert=False, **kwargs):

        existing_docs = [doc for doc in six.itervalues(self._documents)
                         if self._apply_filter(doc, spec)]
        if existing_docs:
            existing_doc = existing_docs[0]  # should find only 1 match
            _id = existing_doc['_id']
            existing_doc.clear()
            existing_doc['_id'] = _id
            existing_doc.update(self._internalize_dict(document))
        elif upsert:
            existing_doc = self._documents[self._insert(document)]

    def _internalize_dict(self, d):
        return {k: copy.deepcopy(v) for k, v in d.items()}

    def remove(self, spec_or_id=None, search_filter=None):
        """Remove objects matching spec_or_id from the collection."""
        if spec_or_id is None:
            spec_or_id = search_filter if search_filter else {}
        if not isinstance(spec_or_id, dict):
            spec_or_id = {'_id': spec_or_id}
        to_delete = list(self.find(spec=spec_or_id))
        for doc in to_delete:
            doc_id = doc['_id']
            del self._documents[doc_id]

        return {
            "connectionId": uuid.uuid4().hex,
            "n": len(to_delete),
            "ok": 1.0,
            "err": None,
        }


class MockMongoDB(object):
    def __init__(self, dbname):
        self._dbname = dbname
        self.mainpulator = None

    def authenticate(self, username, password):
        pass

    def add_son_manipulator(self, manipulator):
        global SON_MANIPULATOR
        SON_MANIPULATOR = manipulator

    def __getattr__(self, name):
        if name == 'authenticate':
            return self.authenticate
        elif name == 'name':
            return self._dbname
        elif name == 'add_son_manipulator':
            return self.add_son_manipulator
        else:
            return get_collection(self._dbname, name)

    def __getitem__(self, name):
        return get_collection(self._dbname, name)


class MockMongoClient(object):
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, dbname):
        return MockMongoDB(dbname)


def get_collection(db_name, collection_name):
    mongo_collection = MockCollection(MockMongoDB(db_name), collection_name)
    return mongo_collection


def pymongo_override():
    global pymongo
    import pymongo
    if pymongo.MongoClient is not MockMongoClient:
        pymongo.MongoClient = MockMongoClient
    if pymongo.MongoReplicaSetClient is not MockMongoClient:
        pymongo.MongoClient = MockMongoClient


class MyTransformer(mongo.BaseTransform):
    """Added here just to check manipulator logic is used correctly."""

    def transform_incoming(self, son, collection):
        return super(MyTransformer, self).transform_incoming(son, collection)

    def transform_outgoing(self, son, collection):
        return super(MyTransformer, self).transform_outgoing(son, collection)


class MongoCache(unit.BaseTestCase):
    def setUp(self):
        super(MongoCache, self).setUp()
        global COLLECTIONS
        COLLECTIONS = {}
        mongo.MongoApi._DB = {}
        mongo.MongoApi._MONGO_COLLS = {}
        pymongo_override()
        # using typical configuration
        self.arguments = {
            'db_hosts': 'localhost:27017',
            'db_name': 'ks_cache',
            'cache_collection': 'cache',
            'username': 'test_user',
            'password': 'test_password'
        }

    def test_missing_db_hosts(self):
        self.arguments.pop('db_hosts')
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_missing_db_name(self):
        self.arguments.pop('db_name')
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_missing_cache_collection_name(self):
        self.arguments.pop('cache_collection')
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_incorrect_write_concern(self):
        self.arguments['w'] = 'one value'
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_correct_write_concern(self):
        self.arguments['w'] = 1
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue10")
        # There is no proxy so can access MongoCacheBackend directly
        self.assertEqual(1, region.backend.api.w)

    def test_incorrect_read_preference(self):
        self.arguments['read_preference'] = 'inValidValue'
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)
        # As per delayed loading of pymongo, read_preference value should
        # still be string and NOT enum
        self.assertEqual('inValidValue', region.backend.api.read_preference)

        random_key = uuid.uuid4().hex
        self.assertRaises(ValueError, region.set,
                          random_key, "dummyValue10")

    def test_correct_read_preference(self):
        self.arguments['read_preference'] = 'secondaryPreferred'
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)
        # As per delayed loading of pymongo, read_preference value should
        # still be string and NOT enum
        self.assertEqual('secondaryPreferred',
                         region.backend.api.read_preference)

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue10")

        # Now as pymongo is loaded so expected read_preference value is enum.
        # There is no proxy so can access MongoCacheBackend directly
        self.assertEqual(3, region.backend.api.read_preference)

    def test_missing_replica_set_name(self):
        self.arguments['use_replica'] = True
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_provided_replica_set_name(self):
        self.arguments['use_replica'] = True
        self.arguments['replicaset_name'] = 'my_replica'
        dp_region.make_region().configure('keystone.cache.mongo',
                                          arguments=self.arguments)
        self.assertTrue(True)  # reached here means no initialization error

    def test_incorrect_mongo_ttl_seconds(self):
        self.arguments['mongo_ttl_seconds'] = 'sixty'
        region = dp_region.make_region()
        self.assertRaises(exception.ValidationError, region.configure,
                          'keystone.cache.mongo',
                          arguments=self.arguments)

    def test_cache_configuration_values_assertion(self):
        self.arguments['use_replica'] = True
        self.arguments['replicaset_name'] = 'my_replica'
        self.arguments['mongo_ttl_seconds'] = 60
        self.arguments['ssl'] = False
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)
        # There is no proxy so can access MongoCacheBackend directly
        self.assertEqual('localhost:27017', region.backend.api.hosts)
        self.assertEqual('ks_cache', region.backend.api.db_name)
        self.assertEqual('cache', region.backend.api.cache_collection)
        self.assertEqual('test_user', region.backend.api.username)
        self.assertEqual('test_password', region.backend.api.password)
        self.assertEqual(True, region.backend.api.use_replica)
        self.assertEqual('my_replica', region.backend.api.replicaset_name)
        self.assertEqual(False, region.backend.api.conn_kwargs['ssl'])
        self.assertEqual(60, region.backend.api.ttl_seconds)

    def test_multiple_region_cache_configuration(self):
        arguments1 = copy.copy(self.arguments)
        arguments1['cache_collection'] = 'cache_region1'

        region1 = dp_region.make_region().configure('keystone.cache.mongo',
                                                    arguments=arguments1)
        # There is no proxy so can access MongoCacheBackend directly
        self.assertEqual('localhost:27017', region1.backend.api.hosts)
        self.assertEqual('ks_cache', region1.backend.api.db_name)
        self.assertEqual('cache_region1', region1.backend.api.cache_collection)
        self.assertEqual('test_user', region1.backend.api.username)
        self.assertEqual('test_password', region1.backend.api.password)
        # Should be None because of delayed initialization
        self.assertIsNone(region1.backend.api._data_manipulator)

        random_key1 = uuid.uuid4().hex
        region1.set(random_key1, "dummyValue10")
        self.assertEqual("dummyValue10", region1.get(random_key1))
        # Now should have initialized
        self.assertIsInstance(region1.backend.api._data_manipulator,
                              mongo.BaseTransform)

        class_name = '%s.%s' % (MyTransformer.__module__, "MyTransformer")

        arguments2 = copy.copy(self.arguments)
        arguments2['cache_collection'] = 'cache_region2'
        arguments2['son_manipulator'] = class_name

        region2 = dp_region.make_region().configure('keystone.cache.mongo',
                                                    arguments=arguments2)
        # There is no proxy so can access MongoCacheBackend directly
        self.assertEqual('localhost:27017', region2.backend.api.hosts)
        self.assertEqual('ks_cache', region2.backend.api.db_name)
        self.assertEqual('cache_region2', region2.backend.api.cache_collection)

        # Should be None because of delayed initialization
        self.assertIsNone(region2.backend.api._data_manipulator)

        random_key = uuid.uuid4().hex
        region2.set(random_key, "dummyValue20")
        self.assertEqual("dummyValue20", region2.get(random_key))
        # Now should have initialized
        self.assertIsInstance(region2.backend.api._data_manipulator,
                              MyTransformer)

        region1.set(random_key1, "dummyValue22")
        self.assertEqual("dummyValue22", region1.get(random_key1))

    def test_typical_configuration(self):

        dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        self.assertTrue(True)  # reached here means no initialization error

    def test_backend_get_missing_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))

    def test_backend_set_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue")
        self.assertEqual("dummyValue", region.get(random_key))

    def test_backend_set_data_with_string_as_valid_ttl(self):

        self.arguments['mongo_ttl_seconds'] = '3600'
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)
        self.assertEqual(3600, region.backend.api.ttl_seconds)
        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue")
        self.assertEqual("dummyValue", region.get(random_key))

    def test_backend_set_data_with_int_as_valid_ttl(self):

        self.arguments['mongo_ttl_seconds'] = 1800
        region = dp_region.make_region().configure('keystone.cache.mongo',
                                                   arguments=self.arguments)
        self.assertEqual(1800, region.backend.api.ttl_seconds)
        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue")
        self.assertEqual("dummyValue", region.get(random_key))

    def test_backend_set_none_as_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        region.set(random_key, None)
        self.assertIsNone(region.get(random_key))

    def test_backend_set_blank_as_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        region.set(random_key, "")
        self.assertEqual("", region.get(random_key))

    def test_backend_set_same_key_multiple_times(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue")
        self.assertEqual("dummyValue", region.get(random_key))

        dict_value = {'key1': 'value1'}
        region.set(random_key, dict_value)
        self.assertEqual(dict_value, region.get(random_key))

        region.set(random_key, "dummyValue2")
        self.assertEqual("dummyValue2", region.get(random_key))

    def test_backend_multi_set_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        random_key = uuid.uuid4().hex
        random_key1 = uuid.uuid4().hex
        random_key2 = uuid.uuid4().hex
        random_key3 = uuid.uuid4().hex
        mapping = {random_key1: 'dummyValue1',
                   random_key2: 'dummyValue2',
                   random_key3: 'dummyValue3'}
        region.set_multi(mapping)
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertFalse(region.get(random_key))
        self.assertEqual("dummyValue1", region.get(random_key1))
        self.assertEqual("dummyValue2", region.get(random_key2))
        self.assertEqual("dummyValue3", region.get(random_key3))

    def test_backend_multi_get_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        random_key = uuid.uuid4().hex
        random_key1 = uuid.uuid4().hex
        random_key2 = uuid.uuid4().hex
        random_key3 = uuid.uuid4().hex
        mapping = {random_key1: 'dummyValue1',
                   random_key2: '',
                   random_key3: 'dummyValue3'}
        region.set_multi(mapping)

        keys = [random_key, random_key1, random_key2, random_key3]
        results = region.get_multi(keys)
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, results[0])
        self.assertEqual("dummyValue1", results[1])
        self.assertEqual("", results[2])
        self.assertEqual("dummyValue3", results[3])

    def test_backend_multi_set_should_update_existing(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        random_key = uuid.uuid4().hex
        random_key1 = uuid.uuid4().hex
        random_key2 = uuid.uuid4().hex
        random_key3 = uuid.uuid4().hex
        mapping = {random_key1: 'dummyValue1',
                   random_key2: 'dummyValue2',
                   random_key3: 'dummyValue3'}
        region.set_multi(mapping)
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertEqual("dummyValue1", region.get(random_key1))
        self.assertEqual("dummyValue2", region.get(random_key2))
        self.assertEqual("dummyValue3", region.get(random_key3))

        mapping = {random_key1: 'dummyValue4',
                   random_key2: 'dummyValue5'}
        region.set_multi(mapping)
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertEqual("dummyValue4", region.get(random_key1))
        self.assertEqual("dummyValue5", region.get(random_key2))
        self.assertEqual("dummyValue3", region.get(random_key3))

    def test_backend_multi_set_get_with_blanks_none(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        random_key = uuid.uuid4().hex
        random_key1 = uuid.uuid4().hex
        random_key2 = uuid.uuid4().hex
        random_key3 = uuid.uuid4().hex
        random_key4 = uuid.uuid4().hex
        mapping = {random_key1: 'dummyValue1',
                   random_key2: None,
                   random_key3: '',
                   random_key4: 'dummyValue4'}
        region.set_multi(mapping)
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertEqual("dummyValue1", region.get(random_key1))
        self.assertIsNone(region.get(random_key2))
        self.assertEqual("", region.get(random_key3))
        self.assertEqual("dummyValue4", region.get(random_key4))

        keys = [random_key, random_key1, random_key2, random_key3, random_key4]
        results = region.get_multi(keys)

        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, results[0])
        self.assertEqual("dummyValue1", results[1])
        self.assertIsNone(results[2])
        self.assertEqual("", results[3])
        self.assertEqual("dummyValue4", results[4])

        mapping = {random_key1: 'dummyValue5',
                   random_key2: 'dummyValue6'}
        region.set_multi(mapping)
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertEqual("dummyValue5", region.get(random_key1))
        self.assertEqual("dummyValue6", region.get(random_key2))
        self.assertEqual("", region.get(random_key3))

    def test_backend_delete_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue")
        self.assertEqual("dummyValue", region.get(random_key))

        region.delete(random_key)
        # should return NO_VALUE as key no longer exists in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))

    def test_backend_multi_delete_data(self):

        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )
        random_key = uuid.uuid4().hex
        random_key1 = uuid.uuid4().hex
        random_key2 = uuid.uuid4().hex
        random_key3 = uuid.uuid4().hex
        mapping = {random_key1: 'dummyValue1',
                   random_key2: 'dummyValue2',
                   random_key3: 'dummyValue3'}
        region.set_multi(mapping)
        # should return NO_VALUE as key does not exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key))
        self.assertEqual("dummyValue1", region.get(random_key1))
        self.assertEqual("dummyValue2", region.get(random_key2))
        self.assertEqual("dummyValue3", region.get(random_key3))
        self.assertEqual(api.NO_VALUE, region.get("InvalidKey"))

        keys = mapping.keys()

        region.delete_multi(keys)

        self.assertEqual(api.NO_VALUE, region.get("InvalidKey"))
        # should return NO_VALUE as keys no longer exist in cache
        self.assertEqual(api.NO_VALUE, region.get(random_key1))
        self.assertEqual(api.NO_VALUE, region.get(random_key2))
        self.assertEqual(api.NO_VALUE, region.get(random_key3))

    def test_additional_crud_method_arguments_support(self):
        """Additional arguments should works across find/insert/update."""

        self.arguments['wtimeout'] = 30000
        self.arguments['j'] = True
        self.arguments['continue_on_error'] = True
        self.arguments['secondary_acceptable_latency_ms'] = 60
        region = dp_region.make_region().configure(
            'keystone.cache.mongo',
            arguments=self.arguments
        )

        # There is no proxy so can access MongoCacheBackend directly
        api_methargs = region.backend.api.meth_kwargs
        self.assertEqual(30000, api_methargs['wtimeout'])
        self.assertEqual(True, api_methargs['j'])
        self.assertEqual(True, api_methargs['continue_on_error'])
        self.assertEqual(60, api_methargs['secondary_acceptable_latency_ms'])

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue1")
        self.assertEqual("dummyValue1", region.get(random_key))

        region.set(random_key, "dummyValue2")
        self.assertEqual("dummyValue2", region.get(random_key))

        random_key = uuid.uuid4().hex
        region.set(random_key, "dummyValue3")
        self.assertEqual("dummyValue3", region.get(random_key))
