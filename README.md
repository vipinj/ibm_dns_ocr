ibm_dns_ocr
===========

This repo contains the code for IBM-NYU DNS OCR work on DNS-IP reputation.
language:python
Explicit Requirements:
networkx
cPickle
Input: 
DNS Trust graph(including domain names, IP addresses, NameServers, Mailserver, Prefixes)
Code Flow
(fx)(filename)

parent_train(train_parent)  // Sets up four variables for iteration (POS_SCORE, NEG_SCORE, POS_SC, NEG_SC)
        -> graph_scores2(new_train) // does the TP FP analysis and dumps the results
                -> bl_propagate2(new_rules) //
                        -> iterate(new_rules) // Calls all the rules

helper functions
iterate - iterates over all rules
rand_split - randomly divides the list into testing/training
dump_graph - writes the graph to the disk

other parameters
p1,p2,p3,p4 for rulesix,ruleseven,ruleeight,rulenine
value tuples 
(0.4,0.4,0.9,0.9)
(0.5,0.5,0.9,0.9)
(0.6,0.6,0.9,0.9)
(0.7,0.7,0.9,0.9)
(0.8,0.8,0.9,0.9)	


