# vim: tabstop=4 shiftwidth=4 softtabstop=4


class DictKvs(dict):
    def set(self, key, value):
        if type(value) is type({}):
            self[key] = value.copy()
        else:
            self[key] = value[:]

    def delete(self, key):
        del self[key]


INMEMDB = DictKvs()


class Base(object):
    def __init__(self, db=None):
        if db is None:
            db = INMEMDB
        elif type(db) is type({}):
            db = DictKvs(db)
        self.db = db
