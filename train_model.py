import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle
import numpy
import os

df = pd.read_csv(r'C:\Users\user\Documents\Projects\Malicious-file-detection-system\data\dataset.csv')
print(df.head())
features = ['E_file','filesize','sus_sections','packer','SizeOfCode','SizeOfImage','NumberOfSections']
for feature in (features):
    if (feature in df.columns):
        print(feature + " exists")
    else:
        print(feature + " Not found")
x = df[features]
y = df['class']
print(f"not Malware samples: {(y == 0).sum()}")
print(f"Malware samples: {(y == 1).sum()}")

print(x.isnull().sum())
x.info()

X_train ,X_test,Y_train,Y_test = train_test_split(x,y,test_size=0.2, random_state=40, stratify=y)
#checking the ratio and stratify
X_train.info()
X_test.info()
Not_Malware_Y_train = (Y_train == 0).sum()
Not_Malware_Y_test = (Y_test == 0).sum()
Malware_Y_train = (Y_train == 1).sum()
Malware_Y_test = (Y_test == 1).sum()
ratio1 = Not_Malware_Y_train / Not_Malware_Y_test
ratio2 = Malware_Y_train / Malware_Y_test
if 4 == round(ratio1) and 4 == round(ratio2):
    print("good ratio about 4")
else:
    print("not good ratio")

