# auth_server_demo
A simple demo of permission control service.
# 数据库操作
* flask db init  # 创建迁移文件夹migrates，只调用一次
* flask db migrate 生成迁移文件
* flask db upgrade 执行迁移文件中的升级
* flask db downgrade 执行迁移文件中的降级
# 初始化管理员账户
* flask create-admin username password

