#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 16:25
@Description : 工厂函数
"""
from flask import Flask
from .exts import init_exts
from .auth.auth_urls import *


def create_app():
    app = Flask(__name__)
    # 配置数据库
    db_uri = 'sqlite:///sqlite3.db'     # sqlite配置
    # db_uri = 'mysql+pymysql://root:123456@127.0.0.1:3306/auto_server_demo'    # mysql配置
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACE_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = 'auto_server_demo'
    app.config['SECRET_KEY'] = 'auto_server_demo'
    app.config['PERMANENT_SESSION_LIFETIME'] = 60*60*24*30
    # 初始化插件
    init_exts(app)
    return app
