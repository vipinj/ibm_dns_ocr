
import new_rules as nr

def chkbl(gr):
    var = raw_input("Enter first blacklist: ")
    var = var.rstrip()
    f1 = open(var,'r')
    var2 = raw_input("Enter second_future blacklist: ")
    var2 = var2.rstrip()
#    f2 = open(var2, 'r')
    var1 = var+".posresult"
    g = open(var1,'w')
    var3 = var+".negresult"
    h = open(var3, 'w')
    parent_blpropagate(gr,f1,var2,g,h)
    h.close()
    g.close()
    f1.close()
    

# code blpropagate to ask for a file 
def parent_blpropagate(gr,f1,var2,g,h): # graph, blacklist1, blacklist2_name, filetowrite_log
    # iterate code for all the rules
    ret = {}
    ret = nr.bl_propagate(gr, var2)
    pre_dict = {}
    for l in f1:
        l = l.rstrip()
        pre_dict[l] = 1
    fp = open(var2, 'r')
    count = 0
    pos = 0
    neg = 0
    mcount = 0
    for ln in fp:  # newly found domains from blacklists
        ln = ln.rstrip()
        if ln not in pre_dict:  # old domains from initial blacklists
            count += 1
            if ln in gr:
                if gr.node[ln]['trust_state'] < 0:
                    pos += 1
                    g.write("%s %f\n" %(ln, ret[ln]))
                else :
                    neg += 1
                    h.write("%s %f\n" %(ln, gr.node[ln]['trust_state']))
            else:
                mcount += 1

    print "Total: "+str(count)
    print "Not in graph: "+str(mcount)
    print "Positive hits: "+str(pos)
    print "Negative: "+str(neg)
    
