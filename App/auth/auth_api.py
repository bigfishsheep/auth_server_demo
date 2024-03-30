#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 17:23 
@Description : 鉴权相关的方法
"""
import uuid

from flask import session
from flask_jwt_extended import create_access_token
from flask_restful import Resource, fields, reqparse, marshal_with

from .auth_models import *
from ..pre_auth import before_receive

login_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'token': fields.String
}

user_fields = {
    'uid': fields.String,
    'username': fields.String
}

resp_user_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'token': fields.Nested(user_fields)
}

resp_users_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'token': fields.List(fields.Nested(user_fields))
}

resp_common_fields = {
    'status': fields.Integer,
    'msg': fields.String,
}

add_user_parser = reqparse.RequestParser()
add_user_parser.add_argument('username', type=str, required=True, help='username is necessary!')
add_user_parser.add_argument('password', type=str, required=True, help='password is necessary!')

update_user_parser = reqparse.RequestParser()
update_user_parser.add_argument('password', type=str, required=True, help='password is necessary!')

add_role_parser = reqparse.RequestParser()
add_role_parser.add_argument('name', type=str, required=True, help='name is necessary!')

update_user_role_parser = reqparse.RequestParser()
update_user_role_parser.add_argument('roles', type=list, location='json', required=True, help='roles is necessary!')

add_auth_parser = reqparse.RequestParser()
add_auth_parser.add_argument('name', type=str, required=True, help='name is necessary!')
add_auth_parser.add_argument('auth', type=str, required=True, help='auth is necessary!')

update_role_auth_parser = reqparse.RequestParser()
update_role_auth_parser.add_argument('auths', type=list, location='json', required=True, help='auths is necessary!')


class Login(Resource):

    @marshal_with(login_fields)
    def post(self):
        args = add_user_parser.parse_args()
        username = args.get('username')
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(args.get('password')):
            token = create_access_token(identity=username)
            auths = []
            for role in user.roles:
                for auth in role.auths:
                    auths.append(auth.auth)
            session[username] = auths
            return {'status': 1,
                    'msg': 'OK',
                    'token': token}
        else:
            return {'status': 0,
                    'msg': 'username or password is wrong!'}


class UserResource(Resource):
    method_decorators = [before_receive]

    @marshal_with(resp_users_fields)
    def get(self):
        users = User.query.all()
        return {
            'status': 1,
            'msg': 'OK',
            'data': users
        }

    @marshal_with(resp_common_fields)
    def post(self):
        args = add_user_parser.parse_args()
        username = args.get('username')
        query_result = User.query.filter_by(username=username)
        if query_result.count() == 0:
            user = User()
            user.uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
            user.username = username
            user.set_password(args.get('password'))
            db.session.add(user)
            db.session.commit()
            return {'status': 1,
                    'msg': 'OK'}
        else:
            return {'status': 0,
                    'msg': 'username is exists!'}


class UserWithUidResource(Resource):
    method_decorators = [before_receive]

    @marshal_with(resp_user_fields)
    def get(self, uid):
        user = User.query.filter_by(uid=uid).first()
        if user is None:
            return {'status': 0,
                    'msg': 'uid is not exists!'}
        return {'status': 1,
                'msg': 'OK',
                'data': user}

    @marshal_with(resp_common_fields)
    def put(self, uid):
        user = User.query.filter_by(uid=uid).first()
        if user is not None:
            args = update_user_parser.parse_args()
            user.set_password(args.get('password'))
            db.session.commit()
            return {'status': 1,
                    'msg': 'OK'}
        else:
            return {'status': 0,
                    'msg': 'user is not exists!'}

    @marshal_with(resp_common_fields)
    def delete(self, uid):
        query_result = User.query.filter_by(uid=uid)
        if query_result.count() != 1:
            return {'status': 0,
                    'msg': 'Can not find user by this uid!'}
        query_result.delete()
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


role_fields = {
    'id': fields.Integer,
    'name': fields.String
}

resp_role_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.Nested(role_fields)
}

resp_roles_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.List(fields.Nested(role_fields))
}


class RoleResource(Resource):
    method_decorators = [before_receive]

    @marshal_with(resp_roles_fields)
    def get(self):
        roles = Role.query.all()
        return {'status': 1,
                'msg': 'OK',
                'data': roles}

    @marshal_with(resp_common_fields)
    def post(self):
        args = add_role_parser.parse_args()
        name = args.get('name')
        query_result = Role.query.filter_by(name=name)
        if query_result.count() == 0:
            role = Role()
            role.name = name
            db.session.add(role)
            db.session.commit()
            return {'status': 1,
                    'msg': 'OK'}
        else:
            return {'status': 0,
                    'msg': 'name is exists!'}


class RoleWithRidResource(Resource):
    method_decorators = [before_receive]

    @marshal_with(resp_role_fields)
    def get(self, rid):
        role = Role.query.get(rid)
        if role is None:
            return {'status': 0,
                    'msg': 'role is not exists!'}
        return {'status': 1,
                'msg': 'OK',
                'data': role}

    @marshal_with(resp_common_fields)
    def put(self, rid):
        role = Role.query.get(rid)
        if role is not None:
            args = add_role_parser.parse_args()
            name = args.get('name')
            query_result = Role.query.filter_by(name=name)
            if query_result.count() == 1 and query_result.first().id != rid:
                return {'status': 0,
                        'msg': 'name is exists!'}
            role.name = name
            db.session.commit()
            return {'status': 1,
                    'msg': 'OK'}
        else:
            return {'status': 0,
                    'msg': 'role is not exists!'}

    @marshal_with(resp_common_fields)
    def delete(self, rid):
        target_role = Role.query.get(rid)
        if target_role is None:
            return {'status': 0,
                    'msg': 'Can not find role by this rid!'}
        db.session.delete(target_role)
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


class UpdateUserRoleResource(Resource):
    method_decorators = [before_receive]

    @marshal_with(resp_common_fields)
    def put(self, uid):
        arg = update_user_role_parser.parse_args()
        user = User.query.filter_by(uid=uid).first()
        if user is None:
            return {'status': 0,
                    'msg': 'Can\'t find user by this uid!'}
        rids = arg.get('roles')
        if len(rids) == 0:
            user.roles = []
            db.session.commit()
            return {'status': 1,
                    'msg': 'This user\'s roles has clear!'}
        user_roles = []
        for rid in rids:
            role = Role.query.get(rid)
            if role is not None:
                user_roles.append(role)
        if len(user_roles) == 0:
            return {'status': 0,
                    'msg': 'There are no valid role in this roles!'}
        user.roles = user_roles
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


auth_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'auth': fields.String
}

resp_auth_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.Nested(auth_fields)
}

resp_auths_fields = {
    'status': fields.Integer,
    'msg': fields.String,
    'data': fields.List(fields.Nested(auth_fields))
}


class AuthResource(Resource):

    method_decorators = [before_receive]

    @marshal_with(resp_auths_fields)
    def get(self):
        auths = Auth.query.all()
        return {'status': 1,
                'msg': 'OK',
                'data': auths}

    @marshal_with(resp_common_fields)
    def post(self):
        args = add_auth_parser.parse_args()
        name = args.get('name')
        auth = args.get('auth')
        query_name_result = Auth.query.filter_by(name=name)
        if query_name_result.count() != 0:
            return {'status': 0,
                    'msg': 'name is exists!'}
        query_auth_result = Auth.query.filter_by(auth=auth)
        if query_auth_result.count() != 0:
            return {'status': 0,
                    'msg': 'auth is exists!'}
        auth_model = Auth()
        auth_model.name = name
        auth_model.auth = auth
        db.session.add(auth_model)
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


class AuthWithAidResource(Resource):

    method_decorators = [before_receive]

    @marshal_with(resp_auth_fields)
    def get(self, aid):
        auth = Auth.query.get(aid)
        if auth is None:
            return {'status': 0,
                    'msg': 'auth is not exists!'}
        return {'status': 1,
                'msg': 'OK',
                'data': auth}

    @marshal_with(resp_common_fields)
    def put(self, aid):
        target_auth = Auth.query.get(aid)
        if target_auth is not None:
            args = add_auth_parser.parse_args()
            name = args.get('name')
            auth = args.get('auth')
            query_name_result = Auth.query.filter_by(name=name)
            if query_name_result.count() == 1 and query_name_result.first().id != aid:
                return {'status': 0,
                        'msg': 'name is exists!'}
            query_auth_result = Auth.query.filter_by(auth=auth)
            if query_auth_result.count() == 1 and query_auth_result.first().id != aid:
                return {'status': 0,
                        'msg': 'auth is exists!'}
            target_auth.name = name
            target_auth.auth = auth
            db.session.commit()
            return {'status': 1,
                    'msg': 'OK'}
        else:
            return {'status': 0,
                    'msg': 'auth is not exists!'}

    @marshal_with(resp_common_fields)
    def delete(self, aid):
        target_auth = Auth.query.get(aid)
        if target_auth is None:
            return {'status': 0,
                    'msg': 'Can\'t find auth by this aid!'}
        db.session.delete(target_auth)
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


class UpdateRoleAuthResource(Resource):

    method_decorators = [before_receive]

    @marshal_with(resp_common_fields)
    def put(self, rid):
        arg = update_role_auth_parser.parse_args()
        target_role = Role.query.get(rid)
        if target_role is None:
            return {'status': 0,
                    'msg': 'Can\'t find role by this rid!'}
        aids = arg.get('auths')
        if len(aids) == 0:
            target_role.auths = []
            db.session.commit()
            return {'status': 1,
                    'msg': 'This role\'s auths has clear!'}
        role_auths = []
        for aid in aids:
            auth = Auth.query.get(aid)
            if auth is not None:
                role_auths.append(auth)
        if len(role_auths) == 0:
            return {'status': 0,
                    'msg': 'There are no valid auth in this auths!'}
        target_role.auths = role_auths
        db.session.commit()
        return {'status': 1,
                'msg': 'OK'}


class RoleWithUidResource(Resource):

    method_decorators = [before_receive]

    @marshal_with(resp_roles_fields)
    def get(self, uid):
        user = User.query.filter_by(uid=uid).first()
        if user is None:
            return {'status': 0,
                    'msg': 'user is not exists!'}
        return {'status': 1,
                'msg': 'OK',
                'data': user.roles}


class AuthWithRidResource(Resource):

    method_decorators = [before_receive]

    @marshal_with(resp_auths_fields)
    def get(self, rid):
        role = Role.query.get(rid)
        if role is None:
            return {'status': 0,
                    'msg': 'role is not exists!'}
        return {'status': 1,
                'msg': 'OK',
                'data': role.auths}
