#!/usr/bin/env python
# This file basically calculates the number of neighbors of good and bad domains - v1 
# 
#and prints them out

import sys
import networkx as nx
import new_rules as nr
import new_train as nt

def naive_clusters(gr):
    f1 = open("benign_neigh",'w')
    f2 = open("mal_neigh",'w')
    for n in gr.nodes():
        if gr.node[n]['trust_state'] < 0:
            f2.write("%s %d\n" %(n, len(gr.neighbors(n))))
        elif gr.node[n]['trust_state'] > 0:
            f1.write("%s %d\n" %(n, len(gr.neighbors(n))))
        else:
            pass
    f1.close()
    f2.close()
def better_clusters(gr):
    gr = nt.reset_trust_graph(gr)
    bl = nr.load_benign("benign50k")
    ml = nr.load_mal("finaldom_list.txt")
    il = nr.load_mal("finalip_list.txt")
    gr = nr.load_benign_graph(bl, gr)
    gr = nr.load_mal_graph(ml, gr)
    gr = nr.load_mal_graph(il, gr)
    f1 = open("benign_neigh2",'w')
    f2 = open("mal_neigh2",'w')
    for n in gr.nodes():
        if gr.node[n]['trust_state'] < 0:
            for e in gr.edge[n]:
                ct1 = 0
                if gr.node[e]['trust_state'] < 0:
                    ct1 += 1
            f2.write("%s, length: %d, mal_number: %d \n" %(n, len(gr.neighbors(n)), ct1))
        elif gr.node[n]['trust_state'] > 0:
            for e in gr.edge[n]:
                ct2 = 0
                if gr.node[e]['trust_state'] > 0:
                    ct2 += 1
            f1.write("%s, length: %d, benign_number: %d \n" %(n, len(gr.neighbors(n)), ct2))
        else:
            pass
    f1.close()
    f2.close()
def better_clusters2(gr):
    gr = nt.reset_trust_graph(gr)
    bl = nr.load_benign("benign50k")
    ml = nr.load_mal("finaldom_list.txt")
    il = nr.load_mal("finalip_list.txt")
    gr = nr.load_benign_graph(bl, gr)
    gr = nr.load_mal_graph(ml, gr)
    gr = nr.load_mal_graph(il, gr)
    f1 = open("benign_neigh3",'w')
    f2 = open("mal_neigh3",'w')
    for n in gr.nodes():
        if gr.node[n]['trust_state'] < 0:
            for e in gr.edge[n]:
                if gr.edge[n][e]['type'] == "A":
                    name = e
                ct1 = 0
                if gr.node[e]['trust_state'] < 0:
                    ct1 += 1
                    for f in gr.edge[e]:
                        if gr.node[f]['trust_state'] > 0:
                            ct1 += 1
            f2.write("%s, length: %d, mal_number: %d \n" %(n, len(gr.neighbors(n)), ct1))
        elif gr.node[n]['trust_state'] > 0:
            for e in gr.edge[n]:
                ct2 = 0
                if gr.node[e]['trust_state'] > 0:
                    ct2 += 1
                    for f in gr.edge[e]:
                        if gr.node[f]['trust_state'] > 0:
                            ct2 += 1
            f1.write("%s, length: %d, benign_number: %d \n" %(n, len(gr.neighbors(n)), ct2))
        else:
            pass
    f1.close()
    f2.close()
            

