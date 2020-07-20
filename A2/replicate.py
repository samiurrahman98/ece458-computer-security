import pandas as pd

output = {}
lsfr1 = [1,1,0]
# lsfr2 = [1,1,0,0,1,0,1]

# lsfr2 = [0,1,0]
lsfr2 = [0,1,0,0,1,1,1]

# lsfr2 = [0,1,1]
# lsfr2 = [1,1,0,1,0,0,1]

# lsfr2 = [1,1,0]
# lsfr2 = [0,1,1,1,0,1,0]

# lsfr2 = [1,1,1]
# lsfr2 = [1,1,1,0,1,0,0]

lsfr3 = [1,0,0,0,1,1,0,1,1,1,0,1,0,1,0,0,0,0,1,0,0,1,0,1,1,0,0,1,1,1,1]
sequence = "1001110111110100101001001001111100001101"

result = ""
for i in range(40):
    x0 = lsfr1[i % len(lsfr1)]
    x1 = lsfr2[i % len(lsfr2)]
    x2 = lsfr3[i % len(lsfr3)]

    result += str(((x0 and not(x1)) ^ (x1 and x2)))
print(sequence)
print(result)