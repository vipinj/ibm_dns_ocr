o#!/usr/bin/env python
import time
from random import randint
from neo4j import GraphDatabase
path = '/home/tierney/Downloads/neo4j-community-1.7/data/graph.db'
_NUM_NODES = 1000000

db = GraphDatabase(path)

def load():
  start = time.time()
  with db.transaction:
    for i in range(_NUM_NODES):
      if (i % 50000 == 0):
        print i
      node = db.node(name=str(i))
  finish = time.time()
  print finish - start

def add_relationships():
  start = time.time()
  with db.transaction:
    for i in range(10000):
      if (i % 1000 == 0):
        print i

      node_a_name = randint(0, _NUM_NODES)
      while True:
        node_b_name = randint(0, _NUM_NODES)
        if node_a_name != node_b_name:
          break
      node_a = db.node(name=str(node_a_name))
      node_b = db.node(name=str(node_b_name))
      relationship = node_a.knows(
        node_b, name = str(node_a_name) + '_' + str(node_b_name))
  finish = time.time()
  print finish - start

def find_relationships():
  with db.transaction:
    for i in range(_NUM_NODES):
      if (i % 50000 == 0):
        print i
      node = db.node(name=str(i))
      if node.knows.single:
        print i, node.knows.single

#add_relationships()
find_relationships()
db.shutdown()
