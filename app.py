#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 16:25
@Description : 启动入口
"""
import uuid

import click
from flask.cli import with_appcontext

from App import create_app
from App.auth.auth_models import User
from App.exts import db

app = create_app()


@app.cli.command()
@with_appcontext
@click.argument('username')
@click.argument('password')
def create_admin(username, password):
    if User.query.filter_by(username=username).first() is not None:
        print(f'用户名{username}已存在!')
        return
    user = User()
    user.uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
    user.username = username
    user.set_password(password)
    db.session.add(user)
    db.session.commit()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)