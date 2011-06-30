# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystone.backends.sqlalchemy import get_session, models, aliased
from keystone.backends.api import BaseGroupAPI

class GroupAPI(BaseGroupAPI):

    def get(self, id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Group).filter_by(id=id).first()
        return result
    
    
    def get_users(self, id, session=None):
        if not session:
            session = get_session()
        result = session.query(models.User).filter_by(\
            group_id=id)
        return result
    
    
    def get_all(self, session=None):
        if not session:
            session = get_session()
        result = session.query(models.Group)
        return result
    
    
    def get_page(self, marker, limit, session=None):
        if not session:
            session = get_session()
    
        if marker:
            return session.query(models.Group).filter("id>:marker").params(\
                                marker='%s' % marker).order_by(\
                                models.Group.id.desc()).limit(limit).all()
        else:
            return session.query(models.Group).order_by(\
                                models.Group.id.desc()).limit(limit).all()
    
    
    def get_page_markers(self, marker, limit, session=None):
        if not session:
            session = get_session()
        first = session.query(models.Group).order_by(\
                            models.Group.id).first()
        last = session.query(models.Group).order_by(\
                            models.Group.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next = session.query(models.Group).filter("id > :marker").params(\
                        marker='%s' % marker).order_by(\
                        models.Group.id).limit(limit).all()
        prev = session.query(models.Group).filter("id < :marker").params(\
                        marker='%s' % marker).order_by(\
                        models.Group.id.desc()).limit(int(limit)).all()
        if len(next) == 0:
            next = last
        else:
            for t in next:
                next = t
        if len(prev) == 0:
            prev = first
        else:
            for t in prev:
                prev = t
        if prev.id == marker:
            prev = None
        else:
            prev = prev.id
        if next.id == last.id:
            next = None
        else:
            next = next.id
        return (prev, next)
    
    
    def delete(self, id, session=None):
        if not session:
            session = get_session()
        with session.begin():
            group_ref = self.get(id, session)
            session.delete(group_ref)
    
    def get_by_user_get_page(self, user_id, marker, limit, session=None):
        if not session:
            session = get_session()
        uga = aliased(models.UserGroupAssociation)
        group = aliased(models.Group)
        if marker:
            return session.query(group, uga).join(\
                                (uga, uga.group_id == group.id)).\
                                filter(uga.user_id == user_id).\
                                filter("id>=:marker").params(
                                marker='%s' % marker).order_by(
                                group.id).limit(limit).all()
        else:
            return session.query(group, uga).\
                                join((uga, uga.group_id == group.id)).\
                                filter(uga.user_id == user_id).order_by(
                                group.id).limit(limit).all()
    
    
    def get_by_user_get_page_markers(self, user_id, marker, limit, session=None):
        if not session:
            session = get_session()
        uga = aliased(models.UserGroupAssociation)
        group = aliased(models.Group)
        first, _firstassoc = session.query(group, uga).\
                            join((uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).\
                            order_by(group.id).first()
        last, _lastassoc = session.query(group, uga).\
                            join((uga, uga.group_id == group.id)).\
                            filter(uga.user_id == user_id).\
                            order_by(group.id.desc()).first()
        if first is None:
            return (None, None)
        if marker is None:
            marker = first.id
        next = session.query(group, uga).join(
                                (uga, uga.group_id == group.id)).\
                                filter(uga.user_id == user_id).\
                                filter("id>=:marker").params(
                                marker='%s' % marker).order_by(
                                group.id).limit(int(limit)).all()
    
        prev = session.query(group, uga).join(
                                (uga, uga.group_id == group.id)).\
                                filter(uga.user_id == user_id).\
                                filter("id < :marker").params(
                                marker='%s' % marker).order_by(
                                group.id).limit(int(limit) + 1).all()
        next_len = len(next)
        prev_len = len(prev)
    
        if next_len == 0:
            next = last
        else:
            for t, _a in next:
                next = t
        if prev_len == 0:
            prev = first
        else:
            for t, _a in prev:
                prev = t
        if first.id == marker:
            prev = None
        else:
            prev = prev.id
        if marker == last.id:
            next = None
        else:
            next = next.id
        return (prev, next)

def get():
    return GroupAPI()