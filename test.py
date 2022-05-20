import numpy as np
import random

test = {}

data = ['apple','boy','apple','cat']
for i in range(len(data)):
    if data[i] in test.keys():
        test[data[i]] = test.get(data[i]) + 1
    else:
        test[data[i]] = 1

print(test)        

index = 0
packets = []
for i in range(0,100):
    n = random.randint(1,3)
    packets.append(n)
    if len(packets) == 10:
        value = np.cumsum(packets)
        print(value)
        print(packets)
        packets.clear()
    
