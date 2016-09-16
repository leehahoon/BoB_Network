import os

os.system("ip route > gateway")
f = open('gateway', 'r')
data = f.read()
gateway = data.split()
f2 = open('gateway','w')
f2.write(gateway[2])
