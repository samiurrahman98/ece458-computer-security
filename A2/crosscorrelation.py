import pandas as pd

lsfr1_output = {}
lsfr3_output = {}
a = [1,0,0,1,1,1,0,1,1,1,1,1,0,1,0,0,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,1,0,0,0,0,1,1,0,1]
b = [1,1,0]
c = [1,1,1,1,1,0,0,0,1,1,0,1,1,1,0,1,0,1,0,0,0,0,1,0,0,1,0,1,1,0,0]

for t in range(40):
    lsfr1_output["c(" + str(t) + ")"] = 0
    lsfr3_output["c(" + str(t) + ")"] = 0
    for i in range(40):
        lsfr1_output["c(" + str(t) + ")"] = lsfr1_output["c(" + str(t) + ")"] + ((-1) ** (a[i] + b[(i + t) % 3]))
        lsfr3_output["c(" + str(t) + ")"] = lsfr3_output["c(" + str(t) + ")"] + ((-1) ** (a[i] + c[(i + t) % 31]))

(pd.DataFrame.from_dict(data=lsfr1_output, orient='index').to_csv('crosscorrelation-lsfr1.csv', header=False))
(pd.DataFrame.from_dict(data=lsfr3_output, orient='index').to_csv('crosscorrelation-lsfr3.csv', header=False))