import csv,os
import pandas as pd

# Extract list of the data checked in the dataset
def Checked_Data():
    os.chdir("Datasets")
    print(os.getcwd())
    #for small datasets
    """
    with open('API_Functions.csv','r',newline='') as file:
        dataset = csv.reader(file)
        for i, row in enumerate(dataset, start=1):
            if i == 0:
                print(row)"""
    #for big datasets
    chunk_size = 100000
    for chunk in pd.read_csv('API_Functions.csv', chunksize=chunk_size):
        print(chunk.columns.tolist())  
        break  


if __name__ == "__main__":
    Checked_Data()
    print("finish")