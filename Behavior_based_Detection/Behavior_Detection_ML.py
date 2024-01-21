import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os

#model
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

os.getcwd()
dataset_path = os.getcwd() +"\Datasets\\DLLs_Imported.csv"
print(dataset_path)
dataset = pd.read_csv(dataset_path) # will enter the dataset path here

print(dataset.head())

print(dataset.isnull().sum())

label_encoder = LabelEncoder()

