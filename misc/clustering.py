

import networkx as nx

def cluster(gr):
    f = open("graph_clustering_output",'w')
    for n in gr.nodes():
        t = nx.clustering(gr,n)
        if t>0:
            f.write("%s, %f\n" %(n, t))
    f.close()
