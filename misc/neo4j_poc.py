#!/usr/bin/env python

import networkx as nx
import sys
from neo4j import GraphDatabase

#path ='/home/jvipin/scratch/ibm_dns_ocr/misc/graphdb/'
path = '/scratch/vipin/working_dns_data/ccs/precision/ibm_dns_ocr/misc/graphdb/'

f = open(sys.argv[1],'r')
db = GraphDatabase(path)
count = 0
for ln in f:
    count += 1
    line = ln.rstrip().split(',')
    if count%10000 == 0:
        print count
#    print line[0],line[1],line[2],line[3],line[4]
    with db.transaction:
        fnode = db.node(name=line[0],ntype=line[2])
        snode = db.node(name=line[1],ntype=line[3])
        rel = fnode.knows(snode,etype=line[4])

db.shutdown()
f.close()
