#!/usr/bin/env python
# part_file to test neo4j poc
import sys
import networkx as nx
import cPickle
f = open(sys.argv[1],'r')
g = open("part_graph_op.txt", 'w')
gr = cPickle.load(f)
f.close()
ct = 0
for n in gr.nodes():
    if ct  == 1500000:
        break
    else:
        ct += 1
        if (ct %10000 == 0):
            print ct
        for e in gr.edge[n]:
            g.write("%s, %s, %s, %s, %s \n" %(n, e, gr.node[n]['type'], gr.node[e]['type'], gr.edge[n][e]['type']))
            
g.close()

