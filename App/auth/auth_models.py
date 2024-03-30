#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 16:49 
@Description : 权限管理相关的模型
"""
from werkzeug.security import generate_password_hash, check_password_hash

from ..exts import db


class User(db.Model):
    __tablename__ = 'tb_user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uid = db.Column(db.String(100), unique=True, index=True)
    username = db.Column(db.String(100), unique=True, index=True)
    password = db.Column(db.String(100))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


user_role = db.Table('tb_user_role',
                     db.Column('uid', db.String(100),
                               db.ForeignKey('tb_user.uid')),
                     db.Column('rid', db.Integer,
                               db.ForeignKey('tb_role.id')),
                     db.PrimaryKeyConstraint('uid', 'rid'))


class Role(db.Model):
    __tablename__ = 'tb_role'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, index=True)
    users = db.relationship('User', backref='roles', secondary=user_role, lazy='dynamic')


role_auth = db.Table('tb_role_auth',
                     db.Column('rid', db.Integer,
                               db.ForeignKey('tb_role.id')),
                     db.Column('aid', db.Integer,
                               db.ForeignKey('tb_auth.id')),
                     db.PrimaryKeyConstraint('rid', 'aid'))


class Auth(db.Model):
    __tablename__ = 'tb_auth'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, index=True)
    auth = db.Column(db.String(100), unique=True, index=True)
    roles = db.relationship('Role', backref='auths', secondary=role_auth, lazy='dynamic')
