import pandas as pd

output = {}
a = [0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1]
for t in range(31):
    output["c(" + str(t) + ")"] = 0
    for i in range(31):
        output["c(" + str(t) + ")"] = output["c(" + str(t) + ")"] + ((-1) ** (a[i] + a[(i + t) % 31]))

(pd.DataFrame.from_dict(data=output, orient='index').to_csv('autocorrelation.csv', header=False))