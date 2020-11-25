#!/usr/bin/env python3
import binascii

'''
KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf
'''

k1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
print("KEY1: " + str(k1))

k2 = int(k1,16) ^ int("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e",16)
k2 = "911404e13f94884eabbec925851240a52fa381ddb79700dd6d0d"
print("KEY2: " + str(k2))
k3 = int(k2,16) ^ int("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1",16)
k3 = "504053b757eafd3d709d6339b140e03d98b9fe62b84add0332cc"
print("KEY3: " + str(k3))

kf = (int(k1,16)^int(k2,16))^(int(k3,16))
kf = "679ce12554e557ada0e38f2e52f126e54240b2576c83c4196cd2"
print("Fusion de llaves: " + str(kf))

flag = int(kf,16) ^ int("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf",16)
flag = "63727970746f7b7830725f69355f61737330633161743176337d"
print(binascii.unhexlify(flag))


