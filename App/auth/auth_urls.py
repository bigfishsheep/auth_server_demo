#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Author      ：Justice
@Date        ：2024/3/30 17:06 
@Description : 权限相关url配置
"""
from App.exts import api
from .auth_api import *

api.add_resource(Login, '/login')
api.add_resource(UserResource, '/users')
api.add_resource(UserWithUidResource, '/users/<string:uid>')
api.add_resource(RoleResource, '/roles')
api.add_resource(RoleWithRidResource, '/roles/<int:rid>')
api.add_resource(UpdateUserRoleResource, '/users/roles/<string:uid>')
api.add_resource(AuthResource, '/auths')
api.add_resource(AuthWithAidResource, '/auths/<int:aid>')
api.add_resource(UpdateRoleAuthResource, '/roles/auths/<int:rid>')
api.add_resource(RoleWithUidResource, '/roles/user/<string:uid>')
api.add_resource(AuthWithRidResource, '/auths/role/<int:rid>')


