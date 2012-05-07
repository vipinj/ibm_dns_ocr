import new_train as nt
def parent_train(gr,dom_file,ip_file):
    
# This function is responsible for calling graph_scores2 for all the iterations
#def parent_graph_scores():
    # There are basically 8 parameters to worry about 
    # The 8 include, NEG_SCORE, POS_SCORE, NEG_SC, POS_SC, and four Pi's and 2 hop
    # NEG_SCORE,NEG_SC E [-0.1,-1], POS_SCORE,POS_SC E[+0.1,1] (steps of 0.1)
    # p1,p2,p3,p4 
    # This series ke3eps pi's as constant and varies the other constants
    i = 0
    j = 0
    k = 0
    l = 0
    g3 = open("tpfp_results.2hop",'w')
    while i<1:
        i += 0.1
        POS_SCORE = i
        j =0 
        while j < 1 :
            j += 0.1
            NEG_SCORE = -j
            k = 0
            while k< 1:
                k += 0.1
                POS_SC = k
                l = 0
                while l<1:
                    l += 0.1
                    NEG_SC = -l
                    nt.graph_scores2(gr,dom_file,ip_file,POS_SCORE,NEG_SCORE,POS_SC,NEG_SC,g3)
                    

    g3.close()
