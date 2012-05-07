#!/usr/bin/env python

# Convert some of the upper case strings in the graph to lower case
import networkx as nx
import cPickle
import sys

f1= open(sys.argv[1],'r')
f2= open(sys.argv[2],'w')
gr = cPickle.load(f1)
f1.close()
count1 = 0
count2 = 0
print gr.number_of_nodes(),gr.number_of_edges()
for n in gr.nodes():
    if n.isupper():
        t = n.lower()
        if t in gr:
            count1 += 1
            for e in gr.edge[n]:
                gr.add_edge(t,e,type=gr.edge[n][e]['type'])
            gr.remove_node(n)
        else:
            count2 += 1
            gr.add_node(t)
            gr.node[t]['type'] = gr.node[n]['type']
            for e in gr.edge[n]:
                gr.add_edge(t,e,type=gr.edge[n][e]['type'])
            gr.remove_node(n)
    else:
        pass

print count1, count2
print gr.number_of_nodes(),gr.number_of_edges()
cPickle.dump(gr,f2)
f2.close()
