import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os


import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn import tree

#model
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier,RandomForestRegressor
from sklearn.metrics import accuracy_score, classification_report



# data preprocessing
os.getcwd()
dataset_path = os.getcwd() +"\Datasets\\DLLs_Imported.csv"
print(dataset_path)
dataset = pd.read_csv(dataset_path) # will enter the dataset path here
dataset = dataset.drop('SHA256', axis=1)

dataset.fillna(dataset.mean(), inplace=True)


#decide the prediction
y = dataset['kernel32.dll']
x = dataset.drop(['kernel32.dll',"SHA256"], axis=1)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)





# Regression
random_forest_c = RandomForestRegressor(n_estimators=10, max_depth=3, random_state=42)
random_forest_c .fit(x_train, y_train)
y_pred = RandomForestRegressor.predict(x_test)

# Predict
f = x.columns
the_first = RandomForestRegressor.estimators_[0]
plt.figure(figsize=(15,6))
tree.sample_tree(the_first, feature_names=f, fontsize=10, filled=True, rounded=True)