#!/usr/bin/env python

# This file identifies clusters in a single and double hop environment, preliminary examination
#The file runs no propagation, but only outputs neighborhoods from pregiven blacklists
# This is needed for the initial motivation of existence of clusters

import networkx as nx
import new_rules as nr
import new_train as nt

# Single hop results are not great, a malicious domain expecting its hosting ip to be malicious 
# in the given blacklists is not very highly probable unless I have a large blacklist

def singlehop_clusters(gr,mal,benign): # gr = networkx graph, malfile_name, benignfile_name
    nr.reset_graph_trust(gr)
    ml = nr.load_mal(mal)
    bl = nr.load_benign(benign)
    
    gr = nr.load_mal_graph(ml,gr) # marks nodes with -ve trust
    gr = nr.load_benign_graph(bl,gr) # marks nodes with +ve trust

    tstr = mal+"_clusters"
    tstr2 = benign+"_clusters"
    f1 = open(tstr,'w')
    f2 = open(tstr2,'w')
    ct1 = 0
    ct2 = 0
    for n in gr.nodes():
        if gr.node[n]['trust_state'] < 0: # malicious
            for e in gr.edge[n]:
                if gr.node[e]['trust_state'] < 0 :
                    ct1 += 1
            if ct1>0:
                f1.write("%d %s %s %s %s \n" %(ct1, n,e, gr.node[n]['type'],gr.node[e]['type']))

        elif gr.node[n]['trust_state'] > 0: # benign
            for e in gr.edge[n]:
                ct2 = 0
                if gr.node[e]['trust_state'] > 0 :
                    ct2 += 1
            if ct2 > 0:
                f2.write("%d %s %s %s %s \n" %(ct2, n,e, gr.node[n]['type'],gr.node[e]['type']))
    f1.close()
    f2.close()
    
    
     
