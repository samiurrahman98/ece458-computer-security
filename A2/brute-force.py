import pandas as pd

output = {}
sequence = [1,0,0,1,1,1,0,1,1,1,1,1,0,1,0,0,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,1,0,0,0,0,1,1,0,1]
initial_state_lsfr1 = [1, 1, 0]
initial_state_lsfr2 = {}
initial_state_lsfr3 = [1, 0, 0, 0, 1]

for i in range(len(sequence)):
    x0 = initial_state_lsfr1[i % len(initial_state_lsfr1)]
    bit_options = [0, 1]
    x2 = initial_state_lsfr3[i % len(initial_state_lsfr3)]

    initial_state_lsfr2[i] = ""
    for x1 in bit_options:
        if ((x0 and not(x1)) ^ (x1 and x2)) == sequence[i]:
            initial_state_lsfr2[i] += str(x1)

for key in range(3):
    print(key, '->', initial_state_lsfr2[key])