#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 16:25
@Description : 统一管理插件
"""
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from loguru import logger

db = SQLAlchemy()
migrate = Migrate()
api = Api()
jwt = JWTManager()
logger.add('flask.log', rotation='50Mb')


def init_exts(app):
    db.init_app(app=app)
    migrate.init_app(app=app, db=db)
    api.init_app(app=app)
    jwt.init_app(app=app)
