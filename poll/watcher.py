import csv
import os
import random
import socket
import tracemalloc
from django.shortcuts import render,redirect
from . import models
import math
from datetime import datetime
from django.contrib.admin.forms import AuthenticationForm
import time, datetime
from hashlib import sha512, sha256
from .resources import *
from .merkleTree import merkleTree
import uuid
from django.conf import settings
import random
import string

# f = open('vehicleList1.csv')

data = []
with open("vehicleList1.csv", "r") as f:
    for line in f:
        data_lines = line.rstrip().split('\t')
        for data_line in data_lines:
            data_indiv = line.rstrip().split(',')
            data.append(data_indiv)

# print(data)
# print(data[0])
for i in data:
    randomString = ''.join(random.choices(string.ascii_letters, k=5))
    n = i[0]
    e = i[1]
    newCar = models.Car(username=randomString, public_key_n = n, public_key_e = e, reputation = 0.5)
    newCar.save()