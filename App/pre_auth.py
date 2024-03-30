#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 16:25
@Description : 判断是否具备权限的方法
"""
from flask import request, session
from flask_jwt_extended import verify_jwt_in_request, decode_token, get_jwt_identity
from loguru import logger


def before_receive(func):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if auth_header:
            verify_jwt_in_request()
            jwt_token = auth_header.split(' ')[1]
            try:
                decode_token(jwt_token)
                identity = get_jwt_identity()
                if identity != 'root' and (request.method + ':' + str(request.url_rule)) not in session[identity]:
                    return {'status': 0,
                            'msg': 'Unauthorized'}, 401
            except Exception as e:
                logger.error(e)
                return {'status': 0,
                        'msg': 'Unauthorized'}, 401
        else:
            return {'status': 0,
                    'msg': 'Authorization is not exists!'}, 401
        return func(*args, **kwargs)

    return wrapper
