import pandas as pd
from sklearn.preprocessing import LabelEncoder

#model
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression

from sklearn.metrics import accuracy_score 

dataset = pd.read_csv('') # will enter the dataset path here

#dup removal example
label = LabelEncoder()
label.fit(dataset.example.drop_duplicates())
dataset.example = label.transform(dataset.example)

