#!/usr/bin/env python
# Do not forget to make the run_logs directory before running this
# Don't forget to make the tpfp_results directory
import sys
sys.path.append("/home/vipin/dnspaper/ip_dns/networkx/networkx-1.5rc1/")

import networkx as nx
import cPickle 
import random
#import rules
import new_rules as nr

MAX_ITERATIONS = 2
nruns = 10000
NEG_SCORE=-0.1 # kinda like the negative threshold for nodes, run tests and figure out a good thres score
POS_SCORE=0.1 # like the positive threshold

#The input list contains a list of malicious ip,domains, begign ip, domains and 

def rand_split(dictionary):
    complete = dictionary.keys()
    for s in range(0,10):
        random.shuffle(complete)
        firsthalf = complete[0:(len(complete)/2)]
#        firsthalf = complete[len(]
        secondhalf = complete[(len(complete)/2)+1:]
#        secondhalf = complete[501:]
        return (firsthalf, secondhalf)

def reset_trust_graph(graph):
    for n in graph.nodes():
        graph.node[n]['trust_state'] = 0
    return graph

# def iterate(num):
#     return rules_dict(num)

def mark_nodes(graph,data):
    for n in data:
        graph.node[n]['trust_state'] = 1
    return graph

# For N-1,N testing
# def parent():
#     for i in range(0,nruns):
#         log_fname = "run_logs/""logrun_"+str(i)
#         (ukdom,kdom) = rand_split(mal_domain.keys()) # known mal and unknow mal domains
#         (ukip,kip) = rand_split(mal_ip.keys()) # known mal and unknow mal IPs

#         gr = reset_trust_graph(graph)
#         gr = mark_nodes(gr,kdom)
#         gr = mark_nodes(gr,kip)
        
#         propagate(gr)
#         # Figure this one out
#         switch = 0 # 1 for N-1-N, 0 for 1
#         # Give it a benign list
#         graph_score2(gr,ukdom,ukip,blist)
#         fp = open(log_fname, 'w')
#         ip_dom_log(ukdom,ukip, blist, fp )
#         fp.close()

# def ip_dom_log(dlist, iplist,blist,fp):
#     # max of dlist is the same as iplist, same as blist
    
#     for i in range(0,len(dlist)):
#         fp.write("%s\t%s\t%s\n" %(dlist[i], iplist[i],blist[i]))
        
# graph = cPickle.load(f1)
# print "Graph loaded"
# f1.close()

# def graph_scores(gr,train_dom_f, train_ip_f, test_dom_f, test_ip_f):
#     test_dom = open(test_dom_f, 'r')
#     test_ip = open(test_ip_f,'r')
#     ret = nr.bl_propagate2(gr,train_dom_f,train_ip_f)

#   # This graph basically consists of neighbors from hop1 and hop2, which are the only entities we want to check, if identified
#     gr2 = nx.Graph()

#     f1 = open("truep_r",'w')
#     f2 = open("falsen_r",'w')
#     f3 = open("falsep_r",'w')
#     f4 = open("truen_r",'w')
    
#     g1 = open(train_dom_f,'r')
#     g2 = open(train_ip_f, 'r')
    
    
#     for node in g1: # domain file
#         node = node.rstrip() 
#         if node in gr:
#             gr2.add_node(node)
#             gr2.node[n]['type'] = gr.node[n]['type']
#             for e in gr.edge[n]:
#                 gr2.add_edge(n,e,type=gr.edge[n][e]['type'])
#                 gr2.node[n]['type'] = gr.node[n]['type']
#                 for f in gr.edge[e]:
#                     gr2.add_edge(f,e,type=gr.edge[f][e]['type'])
#                     gr2.node[f]['type'] = gr.node[f]['type']

#     for node in g2: # IP file
#         node = node.rstrip()
#         if node in gr:
#             gr2.add_node(node)
#             gr2.node[n]['type'] = gr.node[n]['type']
#             for e in gr.edge[n]:
#                 gr2.add_edge(n,e,type=gr.edge[n][e]['type'])
#                 gr2.node[n]['type'] = gr.node[n]['type']
#                 for f in gr.edge[e]:
#                     gr2.add_edge(f,e,type=gr.edge[f][e]['type'])
#                     gr2.node[f]['type'] = gr.node[f]['type']

#     in_graph = 0
#     tp_num = 0
#     fn_num = 0
#     tn_num = 0
#     fp_num = 0 # This is not entirely false positive, but those nodes, which I mark, but they are not in my testing list
#     no_score = 0 # present in graph, but no score
#     t_d = {} # dictionary holding domains and their scores
#     t_i ={} # same as above for IPs
#     not_neighbor = 0 # nodes in training, but not present in the two hop neighborhood
#     not_in_graph = 0 # not present in our original graph
#     neg_more_than_thres = 0 # nodes marked negative, but more than negative threshold
#     pos_less_than_thres = 0 # nodes marked positive, but less than positive threshold
#     for n in test_dom:
#         n = n.rstrip()
#         if n in gr: # Check if it exists in original graph
#             in_graph += 1
#             if n in gr2: # if the node in testing is present in the neighborhood graph of training
#                 if n in ret: # if the node has any trust state other than a zero
#                     if ret[n] < NEG_SCORE:
#                         tp_num += 1
#                         t_d[n] = ret[n]
#                         f1.write("%s %f\n" %(n, t_d[n]))
#                     elif ret[n] > POS_SCORE:
#                         fn_num += 1 # false negative coz it shldnt be here
#                         t_d[n] = ret[n]
#                         f2.write("%s %f\n" %(n, t_d[n]))
#                     else:
#                         pass # ret doesn't score values == 0
#                 else :
#                     # decision to mark nodes, which are present in the training neighborhood, but not marked as anything -> false negatives(strict)
#                     no_score += 1 
#                     # Here I can decide whether to use fn_num as false negative or use fn_num + no_score as the nodes to consider for false negatives.
#             else:
#                 not_neighbor += 1 # They are not present in the testing neighborhood
#         else:
#             not_in_graph += 1
#             pass # not even present in original graph

#     for n in test_ip:
#         n = n.rstrip() 
#         if n in gr:
#             in_graph += 1
#             if n in gr2: # the nodes in testing to be in the neighborhood of the training
#                 if n in ret:
#                     if ret[n] < 0:
#                         if ret[n] < NEG_SCORE:
#                             tp_num += 1
#                             t_i[n] = ret[n]
#                             f1.write("%s %f\n" %(n, t_d[n]))
#                         elif ret[n] > POS_SCORE:
#                             fn_num += 1
#                             t_i[n] = ret[n]
#                             f2.write("%s %f\n" %(n, t_d[n]))
#                         else:
#                             pass
#                     else :# Again decide to use fn_num or fn_num + no_score
#                         no_score += 1 
#                 else:
#                     not_neighbor += 1
#             else:
#                 pass # just not present in the graph

#     for i in ret: # nodes for which we have non zero scores a
#         if i in t_d: 
#             continue
#         elif i in t_i:
#             continue 
#         else: # which are not present in the neighborhoods
#             if ret[i] > 0 and ret[i] < POS_SCORE:
#                 pos_less_than_thres += 1
#                 continue
#             elif ret[i] > POS_SCORE: # nodes marked as benign
#                 tn_num += 1
#                 f4.write("%s %f\n" %(i,ret[i]))
#                 continue
#             elif ret[i] < 0 and ret[i] > NEG_SCORE:
#                 neg_more_than_thres += 1
#                 continue
#             elif ret[i] < NEG_SCORE: # nodes marked as malicious
#                 fp_num += 1
#                 f3.write("%s %f\n" %(i,ret[i]))
#                 continue


#     print "tp_num: "+str(tp_num)
#     print "fp_num: "+str(fp_num)
#     print "tn_num: "+str(tn_num)
#     print "fn_num: "+str(fn_num)
#     print "Present in neighbohood, but no score(marked as false negatives): "+str(no_score)
#     print "not_neighbor: "+str(not_neighbor)
#     print "not_in_graph: "+str(not_in_graph)
#     print "Negative more than threshold: "+str(neg_more_than_thres)
#     print "Positive less than threshold: "+str(pos_less_than_thres)
def identify_clusters(gr,i,fp1,fp2): # fp1 for +ve clusters, fp2 for -ve clusters
    for n in gr.nodes():
        npos = 0
        nneg = 0
        ntotal = 0
        if i == 1: # one hop
            if gr.node['trust_state'] < NEG_SCORE:
                for e in gr.edge[n]:
                    ntotal += 1
                    if gr.node[e]['trust_state'] < NEG_SCORE:
                        nneg += 1
                    elif gr.node[e]['trust_state'] > POS_SCORE:
                        npos += 1
                    else:
                        pass
                if npos > nneg:
                    continue
                elif npos < nneg:
                    fp2.write("%s %d %f %d %d\n" %(n,ntotal, gr.node[n]['trust_state'], npos, nneg))
                else:
                    pass
            elif gr.node['trust_state'] > POS_SCORE:
                for e in gr.edge[n]:
                    ntotal += 1
                    if gr.node[e]['trust_state'] > POS_SCORE:
                        npos += 1
                    elif gr.node[e]['trust_state'] < NEG_SCORE:
                        nneg += 1
                    else:
                        pass
                if npos > nneg:
                    fp1.write("%s %d %f %d %d\n" %(n,ntotal, gr.node[n]['trust_state'], npos, nneg))
                elif npos < nneg:
                    continue
                else:
                    pass
            else:
                pass
        elif i == 2: # two hop
            if gr.node['trust_state'] < NEG_SCORE:
                for e in gr.edge[n]:
                    ntotal += 1
                    if gr.node[e]['trust_state'] < NEG_SCORE:
                        nneg += 1
                    elif gr.node[e]['trust_state'] > POS_SCORE:
                        npos += 1
                    else:
                        pass
                    for f in gr.edge[e]:
                        ntotal += 1
                        if gr.node[f]['trust_state'] < NEG_SCORE :
                            nneg += 1
                        elif gr.node[f]['trust_state'] > POS_SCORE:
                            npos += 1
                        else:
                            pass
                if npos > nneg:
                    continue
                elif npos < nneg:
                    fp2.write("%s %d %f %d %d\n" %(n,ntotal, gr.node[n]['trust_state'], npos, nneg))
                else:
                    pass
            elif gr.node['trust_state'] > POS_SCORE:
                for e in gr.edge[n]:
                    ntotal += 1
                    if gr.node[e]['trust_state'] < NEG_SCORE:
                        nneg += 1
                    elif gr.node[e]['trust_state'] > POS_SCORE:
                        npos += 1
                    else:
                        pass
                    for f in gr.edge[e]:
                        ntotal += 1
                        if gr.node[f]['trust_state'] < NEG_SCORE :
                            nneg += 1
                        elif gr.node[f]['trust_state'] > POS_SCORE:
                            npos += 1
                        else:
                            pass
                if npos > nneg:
                    fp1.write("%s %d %f %d %d\n" %(n,ntotal, gr.node[n]['trust_state'], npos, nneg))
                elif npos < nneg:
                    continue
                else:
                    pass
            else:
                continue
        else:
            print "invalid hop propagation value\n"
            break

                
def graph_scores2(gr,dom_file, ip_file,POS_SCORE,NEG_SCORE,POS_SC,NEG_SC,g3, level): #level is for 1 or 2 hop propagation
    g1 = open(dom_file, 'r')
    g2 = open(ip_file, 'r')
#    g3 = open("tpfp_reusults", 'w')
    dom_list = {} # put it in a dictionary
    ip_list = {} # put it an another dictionary
    for n in g1:
        n = n.rstrip()
        dom_list[n] = 1
    g1.close()
    for i in g2:
        i = i.rstrip()
        ip_list[i] = 1
    g2.close()
    for step in range(1,MAX_ITERATIONS):         # Steps are the number of iterations
#        num = MAX_ITERATIONS-1
        (train_dom,test_dom) = rand_split(dom_list)
        (train_ip, test_ip) = rand_split(ip_list)
        ret = nr.bl_propagate2(gr,train_dom,train_ip,0,POS_SC,NEG_SC) 
        ret = nr.bl_propagate2(gr,train_dom,train_ip,1,POS_SC,NEG_SC) 
        # ret = nr.bl_propagate2(gr,train_dom,train_ip,1)
        # ret = nr.bl_propagate2(gr,train_dom,train_ip,2)
        # ret = nr.bl_propagate2(gr,train_dom,train_ip,3)
        # This graph basically consists of neighbors from hop1 and hop2, which are the only entities we want to check, if identified
#        gr2 = nx.Graph()
        
        str1 = "tpfp-results/truep_r"+str(step)
        str2 = "tpfp-results/falsen_r"+str(step)
        str3 = "tpfp-results/falsep_r"+str(step)
        str4 = "tpfp-results/truen_r"+str(step)
        f1= open(str1, 'w')
        f2= open(str2, 'w')
        f3= open(str3, 'w')
        f4= open(str4, 'w')

        print "Now preparing new graph(dictionary)..."

# There are three ways to create the two hop neighborhood, 1.Make a temporary graph, 2. Make a subgraph, 3. Make a dictionary
# http://networkx.lanl.gov/reference/generated/networkx.Graph.subgraph.html ( They are only pointers to original graph)
        
        dom_ip_neigh = {}  # lookups in dictionary are optimized
#        ip_neigh = {}
        for node in dom_list: # domain file
            node = node.rstrip()  # might not be of any use now
            dom_ip_neigh[node]=1
            if node in gr:
                n = node
                for e in gr.edge[n]:
                    dom_ip_neigh[e] = 1
                    if level ==2:
                        for f in gr.edge[e]:
                            dom_ip_neigh[f] = 1

        for node in ip_list: # IP file
            node = node.rstrip() # again, might not be of any use
            if node in gr:
                n = node
                dom_ip_neigh[n]=1
                for e in gr.edge[n]:
                    dom_ip_neigh[e]=1
                    if level == 2:
                        for f in gr.edge[e]:
                            dom_ip_neigh[f] =1
                        
        print "Done preparing new graph..."

        in_graph = 0
        tp_num = 0
        fn_num = 0
        tn_num = 0
        fp_num = 0 # This is not entirely false positive, but those nodes, which I mark, but they are not in my testing list
        no_score = 0 # present in graph, but no score
        t_d = {} # dictionary holding domains and their scores
        t_i ={} # same as above for IPs
        is_neighbor = 0 # marks the nodes which are present in the graph & testing neighborhood
        not_neighbor = 0 # nodes in training, but not present in the two hop neighborhood
        not_in_graph = 0 # not present in our original graph
        neg_more_than_thres = 0 # nodes marked negative, but more than negative threshold
        pos_less_than_thres = 0 # nodes marked positive, but less than positive threshold
        pos_more_than_thres = 0
        neg_less_than_thres = 0
        print "Now starting tp,fp analysis..."
        for n in test_dom:
            n = n.rstrip()
            if n in gr: # Check if it exists in original graph
                in_graph += 1
                if n in dom_ip_neigh: # if the node in testing is present in the neighborhood graph of training
                    is_neighbor += 1
                    if n in ret: # if the node has any trust state other than a zero
                        if ret[n] < NEG_SCORE:
                            tp_num += 1
                            t_d[n] = ret[n]
                            f1.write("%s %f\n" %(n, t_d[n]))
                        elif ret[n] > POS_SCORE:
                            fn_num += 1 # false negative coz it shldnt be here
                            t_d[n] = ret[n]
                            f2.write("%s %f\n" %(n, t_d[n]))
                        else:
                            pass # ret doesn't score values == 0
                    else :
                        # decision to mark nodes, which are present in the training neighborhood, but not marked as anything -> false negatives(strict)
                        no_score += 1 
                        # Here I can decide whether to use fn_num as false negative or use fn_num + no_score as the nodes to consider for false negatives.
                else:
                    not_neighbor += 1 # They are not present in the testing neighborhood
            else:
                not_in_graph += 1
                pass # not even present in original graph

        for k in test_ip:
            k = k.rstrip() 
            if k in gr:
                in_graph += 1
                if k in dom_ip_neigh: # the nodes in testing to be in the neighborhood of the training
                    is_neighbor += 1
                    if k in ret:
                        if ret[k] < NEG_SCORE:
                            tp_num += 1
                            t_i[k] = ret[k]
                            f1.write("%s %f\n" %(k, t_i[k]))
                        elif ret[k] > POS_SCORE:
                            fn_num += 1
                            t_i[k] = ret[k]
                            f2.write("%s %f\n" %(k, t_i[k]))
                        else:
                            pass
                    else :# Again decide to use fn_num or fn_num + no_score
                        no_score += 1 
                else:
                    not_neighbor += 1
            else:
                pass # just not present in the graph

        for i in ret: # nodes for which we have non zero scores a
            if i in t_d: 
                continue
            elif i in t_i:
                continue 
            else: # which are not present in the neighborhoods
                if ret[i] > 0 and ret[i] < POS_SCORE:
                    pos_less_than_thres += 1
                    continue
                elif ret[i] > POS_SCORE: # nodes marked as benign, contribute to TN
                    pos_more_than_thres += 1
#                    tn_num += 1
#                    f4.write("%s %f\n" %(i,ret[i]))
                    continue
                elif ret[i] < 0 and ret[i] > NEG_SCORE:
                    neg_more_than_thres += 1
                    continue
                elif ret[i] < NEG_SCORE: # nodes marked as malicious, contribute to FP
                    neg_less_than_thres += 1
#                    fp_num += 1
                    f3.write("%s %f\n" %(i,ret[i]))
                    continue
                
        identify_clusters(gr,level, fp1, fp2)
        print "Finished with tp/fp analysis"
        print "Values: POS_SCORE: %f, NEG_SCORE: %f, POS_SC: %f, NEG_SC: %f\n" %(POS_SCORE,NEG_SCORE, POS_SC, NEG_SC)
        print "Step(iteration): "+str(step)
        print "tp_num: "+str(tp_num)
        print "fp_num: "+str(neg_less_than_thres)
        print "tn_num: "+str(tn_num)
        print "fn_num: "+str(fn_num)
        print "Present in neighbohood, but no score(should be marked as false negatives?): "+str(no_score)
        print "is neighbor(of testing): "+str(is_neighbor)
        print "not_neighbor: "+str(not_neighbor)
        print "not_in_graph: "+str(not_in_graph)
        print "Negative more than threshold: "+str(neg_more_than_thres)
        print "Positive less than threshold: "+str(pos_less_than_thres)
        print "Positive more than threshold(tn): "+str(pos_more_than_thres)
        print "Negative less than threshold(fp): "+str(neg_less_than_thres)
#        gr2.clear()
        f1.close()
        f2.close()
        f3.close()
        f4.close()
        g3.write("###################### Iteration: %d ######################\n" %(step))
        g3.write("Values: POS_SCORE: %f, NEG_SCORE: %f, POS_SC: %f, NEG_SC: %f\n" %(POS_SCORE,NEG_SCORE, POS_SC, NEG_SC))
        g3.write("tp_num: %d\n" %(tp_num))
        g3.write("fp_num: %d\n" %(fp_num))
        g3.write("tn_num: %d\n" %(tn_num))
        g3.write("fn_num: %d\n" %(fn_num))
        g3.write("is neighbor(of testing): %d\n" %(is_neighbor))
        g3.write("Present in neighborhood, but no score(should be marked as false -ves: %d ?\n" %(no_score))
        g3.write("not_neighbor: %d\n" %(not_neighbor))
        g3.write("not_in_graph: %d\n" %(not_in_graph))
        g3.write("Negative more than threshold: %d\n" %(neg_more_than_thres))
        g3.write("Positive less than threshold: %d\n" %(pos_less_than_thres))
        g3.write("Negative less than threshold(fp): %d\n" %(neg_less_than_thres))
        g3.write("Positive more than threshold(tn): %d\n" %(pos_more_than_thres))
        g3.write("\n")
        g3.flush()

# End of graph_scores2


