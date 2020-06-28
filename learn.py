import os
import sys
import time
import base64
import csv
import numpy as np
from sklearn.model_selection import train_test_split

from pyod.models.knn import KNN
from pyod.utils.data import generate_data
from pyod.utils.data import evaluate_print
from pyod.utils.example import visualize
from pyod.utils.utility import standardizer

def remove_annotation(data):
    # remove last column
    return np.delete(data, data.shape[1] - 1, 1)

def load_data():
    data_np = np.genfromtxt('model1.csv', delimiter=';')
    data_raw = csv.reader(open("model1.csv", "r"), delimiter=';')
    return data_np, list(data_raw)

def normalize_data(data):
    return standardizer(data)

def create_model():
    return KNN()

if __name__ == "__main__":
    data_orig, raw = load_data()
    data = normalize_data(remove_annotation(data_orig))
    model = create_model()
    model.fit(data)

    labels = model.labels_

    for i, elem in enumerate(labels):
        print("%d (%s): %d" % (i, base64.b64decode(raw[i][-1]), elem))

