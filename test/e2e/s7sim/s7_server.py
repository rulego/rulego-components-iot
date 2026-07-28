"""S7 模拟服务：DB1.DBD0=25.5、DB1.DBD4=80.25，监听 102（snap7 客户端固定连 102，需 root 绑定）。"""
import ctypes
import struct
import time

import snap7
from snap7.types import srvAreaDB

server = snap7.server.Server()
db1 = (ctypes.c_uint8 * 64)()
struct.pack_into('>f', db1, 0, 25.5)   # DB1.DBD0 FLOAT32
struct.pack_into('>f', db1, 4, 80.25)  # DB1.DBD4 FLOAT32
server.register_area(srvAreaDB, 1, db1)
server.start()
print('snap7 server listening on :102', flush=True)
while True:
    time.sleep(3600)
