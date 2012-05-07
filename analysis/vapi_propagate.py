#!/usr/bin/env python

import networkx as nx

def wrapper(gr):
  print "----------------------------------------------------------------------------------"
  print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
  print "Rule 2: Generate potential malicious Dnsnames from malicious IPs"
  print "Rule 3: Generate potential malicious Dnsnames from malicious Nameservers"
  print "Rule 4: Generate potential malicious IPs from malicious Prefixes"
  print "Rule 5: Probabilistic rule marking nameservers hosting %x of malicious domain names"
  print "Rule 6: Probabilistic rule marking IPs hosting %x of malicious domain names"
  print "Rule 7: Probabilistic rule marking prefix containing  %x of malicious ips"
  print "Rule 8: Probabilistic rule marking mailserver containing  %x of malicious domains"
  print "Rule 9: Generate potential malicious DNSnames from malicious MailServers"
  print "----------------------------------------------------------------------------------"
  counter = 0
  try:
    while True:
      r1 = raw_input("Enter a rule? (y/n/clear) : ")
      counter += 1
      if r1 == 'n': 
        print "Exit."
        break 
      elif r1.rstrip() == "clear":
        reset_graph_trust(gr)
      else:
        if counter == 1:
          reset_graph_trust(gr)
        rule = raw_input("Please Enter the rule({1-4} or {5-7): ")
        malf = str(raw_input("Please Enter the malicious filename: "))
        mal_list = load_mal(malf)
        gr = load_mal_graph(mal_list, gr)
        benignf = str(raw_input("Please Enter the benign filename: "))
        benign_list = load_mal(benignf)
        gr = load_benign_graph(benign_list, gr)
        gr = iterate(gr, rule)
  except:
    print "Error applying more rules"
    pass
#End of wrapper() ###########    

def ruleone(graph,g):
#  print "reached in rule one"
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Address":
      try:
        if graph.node[n]['trust_state'] == -1:
          for e in graph.edge[n]:
           # Names hosted at a malicious IP are potentially malicious
            try:
              if graph.edge[n][e]['type'] == "A":
                 # Nameservers are appended with a . at the end, for e.g. ns1.google.com. is a NS, not a domain (ns1.google.com)
                temp = e + "."
                if temp in graph:
                  print >>g, ("NameServer %s is possibly malicious because it is hosted at %s" % (e,n))
                  if graph.node[temp]['trust_state'] == 0:
                    graph.node[temp]['trust_state'] = -1
                  else:
                    graph.node[temp]['trust_state'] = -1 + graph.node[temp]['trust_state']
            except KeyError:
              print "No type on edge %s - %s" % (e,n)
      except:
        print "Error in trust state code ?"
  return graph

def ruletwo(graph,g):
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Address":
#      if len(graph.neighbors(n)) >= 10: # 10 is a pure random number on whim, The only concept behind this is to avoid isolated nodes
#        if graph.degree(n) <= 100: # nodes > 100 are definitely a hosting provider, so be cautious and not mark them
      if graph.node[n]['trust_state'] == -1:
        pm = -float(1)/graph.degree(n) # Each neighbor node gets a score divided by the degree
        for e in graph.edge[n]:
          # Names hosted at a malicious IP are potential malicious
          try:
            if graph.edge[n][e]['type'] == "A":
              print >>g, ("Name %s is possibly malicious because it is hosted at %s" % (e,n))
              if graph.node[e]['trust_state'] == 0:
                graph.node[e]['trust_state'] = pm
              else:
                graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
          except KeyError:
            print "No type on edge %s - %s" % (e,n)
          else:
            pass
        else:
          pass
      else:
        pass
    else:
      pass
  return graph

def rulethree(graph,g):
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "NameServer":
#        if len(gr.neighbors(n)) >= 5:
        if graph.node[n]['trust_state'] == -1:
          pm = -float(1)/graph.degree(n) # Each neighbor node gets a score divided by the degree
          for e in graph.edge[n]:
              # Names resolved by a malicious NameServer are potential malicious
            print >>g, ("Name %s is possibly malicious because it is resolved by %s" % (e,n))
            if graph.node[e]['trust_state'] == 0:
              graph.node[e]['trust_state'] = pm
            else:
              graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
    except KeyError:
      print "No type on edge %s - %s" % (e,n)
  return graph

def rulefour(graph,g):
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "IPv4Prefix":
        if graph.node[n]["trust_state"] == -1:
          pm = -float(1)/graph.degree(n)
          for e in graph.edge[n]:
            print >> g, ("IP %s is malicious as it is presented in the malicious Prefix %s" %(e,n))
            if graph.node[e]['trust_state'] == 0:
              graph.node[e]['trust_state'] = pm
            else:
              graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
    except KeyError:
      print "No type on edge %s - %s" %(e,n)
  return graph

# def rulefour_temp(graph,g):
#   for n in graph.nodes():
#     if graph.node[n]['type'] == "DNSName":
#       if graph.node[n]['trust_state'] == 1:
#         for e in graph.edge[n]:
#           try:
#             if graph.edge[n][e]['type'] == "A":
#               print >>g, ("IP %s is possibly malicious because it is hosting %s" % (e,n))
#               graph.node[e]['trust_state'] = pm
#           except KeyError:
#             print "No type on edge %s - %s" % (e,n)
#   return graph
      
def rulefive(graph,g):
#  h = open("r5_op_condensed",'w')  
#  p2 = float(raw_input("Please enter the ratio:"))
#  print "Ratio: ", p2
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "NameServer":
        if graph.node[n]['trust_state'] == 0:
          allnodes = 0.0
          malnodes = 0.0
          malscore = 0.0
          npos = 0
          pos_score = 0
          neg_score = 0
          for e in graph.edge[n]:
            if graph.node[e]['type'] == "DNSName":
              allnodes += 1
              if graph.node[e]['trust_state'] > 0:
                npos += 1
                pos_score += graph.node[e]['trust_state']
              elif graph.node[e]['trust_state'] < 0:
#          malscore += graph.node[e]['trust_state'] # Irrespective of +ve/-ve, if n(+ve) 
                malnodes += 1 
                neg_score += graph.node[e]['trust_state']
              else:
                pass
#          if (float(malnodes)/allnodes) > p2:
#            print >>g, ("Marking NameServer %s as possibly malicious because it has %d%% of malicious neighbors" % (n, (float(malnodes)/allnodes)*100 ))
          if malnodes > npos:
            neg_score += -1
          elif malnodes < npos:
            pos_score += 1
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
#          if malnodes >= 2 and (float(malnodes/allnodes)) > p2 :
          if malnodes >= 10:
            print >>h, n,("NameServer (domains) Total: %d Malicious: %d --" %(allnodes, malnodes)), ((float(malnodes)/allnodes)*100), "%neighbors"
    except KeyError:
      print  "No type on edge %s - %s" % (e,n)
  return graph

def rulesix(graph,g):
#  p1 = float(raw_input("Please enter the ratio:"))
#  print "Ratio: ", p1
  h = open("r6_op_condensed",'w')
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Address":
      if graph.node[n]['trust_state'] == 0:
        arecs = 0.0
        mal_arecs = 0.0
        npos = 0
        neg_score = 0.0
        pos_score = 0.0
        for e in graph.edge[n]:
          if graph.edge[n][e]['type'] == 'A':
            arecs += 1
            if graph.node[e]['trust_state'] < 0:
              mal_arecs += 1
              neg_score += graph.node[e]['trust_state']
            elif graph.node[e]['trust_state'] > 0:
              npos += 1
              pos_score += graph.node[e]['trust_state']
            else:
              pass
        try:
#          if (float(mal_arecs)/arecs) > p1:
          if npos > mal_arecs:
              pos_score += 1
          elif npos < mal_arecs:
            neg_score += -1
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
#          if malnodes >= 2 and (float(malnodes/allnodes)) > p2 :
#          print >>g, ("Marking IP %s as malicious because %f%% of names that point to it are known malicious" % (n,(float(mal_arecs)/arecs)*100))
        except:
          continue
#        if mal_arecs >= 10 and (float(mal_arecs)/arecs) > p1:
        if mal_arecs >= 10:
          print >>h, n,("Domains Total: %d Malicious: %d --" %(arecs,mal_arecs)), ((float(mal_arecs)/arecs)*100), "%neighbors"
  return graph
            
def ruleseven(graph,g):
#  p3 = float(raw_input("Please enter the ratio:"))
#  print "Ratio: ", p3
  h = open("r7_op_condensed",'w')
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Prefix":
      if graph.node[n]["trust_state"] == 0:
        allnodes = 0.0
        malnodes = 0.0
        npos = 0
        pos_score = 0.0
        neg_score = 0.0
        for e in graph.edge[n]:
          allnodes += 1
          if graph.node[e]['trust_state'] < 0:
            malnodes += 1
            neg_score += graph.node[e]['trust_state']
          elif graph.node[e]['trust_state'] > 0:
            npos += 1
            pos_score += graph.node[e]['trust_state']
          else:
            pass
        try:
          if npos > malnodes:
            pos_score += 1
          elif npos < malnodes:
            neg_score += -1
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
        except:
          continue
#        if malnodes >10 and (float(malnodes)/allnodes) > p3:
        if malnodes >10:
          print >>h, n, ("Prefix(IPs) Total: %d Malicious: %d --" %(allnodes, malnodes)), ((float(malnodes)/allnodes)*100), "%neighbors"
  return graph

def ruleeight(graph,g):
  p4 = float(raw_input("Please enter the ratio:"))
  print "Ratio: ", p4
  h = open("r8_op_condensed",'w')
  for n in graph.nodes():
    if graph.node[n]['type'] == "MailServer":
      if graph.node[n]["trust_state"] == 0:
        allnodes = 0.0
        malnodes = 0.0
        npos = 0
        pos_score = 0.0
        neg_score = 0.0
        for e in graph.edge[n]:
          allnodes += 1
          if graph.node[e]['trust_state'] < 0:
            malnodes += 1
            neg_score += graph.node[e]['trust_state']
          elif graph.node[e]['trust_state'] > 0:
            npos += 1
            pos_score += graph.node[e]['trust_state']
          else:
            pass
          try:
          if npos > malnodes:
            pos_score += 1
          elif npos < malnodes:
            neg_score += -1
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
        except:
          continue
#        if malnodes >10 and (float(malnodes)/allnodes) > p4:
        if malnodes >10 : # Pure hypothetical number, it should be difference for MX, NS and/or Prefixes
          print >>h, n, ("MailServer(domains) Total: %d Malicious: %d --" %(allnodes, malnodes)), ((float(malnodes)/allnodes)*100), "%neighbors"
  return graph

def rulenine(graph,g):
  for n in graph.nodes():
    if graph.node[n]['type'] =="MailServer":
      if graph.node[n]['trust_state'] <= -1:
        pm = -float(1)/graph.degree(n)
        for e in graph.edge[n]:
                   # Names hosted at a malicious IP are potential malicious
          try:
            if graph.edge[n][e]['type'] == "MX":
#              print >>g, ("Name %s is possibly malicious because it is hosted(mailserver) at %s" % (e,n))
              if graph.node[e]['trust_state'] == 0:
                graph.node[e]['trust_state'] = pm
              else:
                graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
          except KeyError:
            print "No type on edge %s - %s" % (e,n)
  return graph
    

def reset_graph_trust(g):
  print "Resetting graph trust states...",
  for n in g.nodes():
    g.node[n]['trust_state'] = 0
  print "done."

def rand_split_half(dictionary):
  complete = dictionary.keys()
  for s in range(0,10):
    random.shuffle(complete)
  firsthalf = complete[0:(len(complete)/2)]
  secondhalf = complete[(len(complete)/2)+1:]
  return (firsthalf, secondhalf)
    
def test_graph(g, nodes):
  all_cnt = 0.1
  ing_cnt = 0.1
  mal_cnt = 0.1
  for n in nodes:
    all_cnt += 1
    if n in g:
      ing_cnt += 1
      if g.node[n]['trust_state'] > 0:
        mal_cnt += 1
  ingraphpct = (float(ing_cnt)/all_cnt) * 100
  mal_pct = (float(mal_cnt)/ing_cnt) * 100
  print "GTT:Tested: %d, In graph: %d, M or PM: %d (%f%% of in-graph nodes)" % (all_cnt, ing_cnt, mal_cnt, mal_pct)

# Graph Loading Function
def load_graph(graphpath):
  picklefile = open(graphpath)
  print "Loading graph..."
  graph = []
  graph = cPickle.load(picklefile)
  picklefile.close()
  print "Graph Loaded"
#  reset_graph_trust(graph)
  return graph
#Load Malicious ip/dom list
def load_mal(filename):
  tmp = open(filename,'r')
  mal_list={}
  for ln in tmp:
    ln = ln.rstrip()
    mal_list[ln] = 1
  tmp.close()
  return mal_list

def load_benign(filename):
  tmp = open(filename,'r')
  benign_list={}
  for ln in tmp:
    ln = ln.rstrip()
    benign_list[ln] = +1
  tmp.close()
  return benign_list
  
def load_mal_graph(mal_list, graph):
  count = 0
  for line in mal_list:
    if line in graph:
      graph.node[line]['trust_state'] = -1
      count+=1
  print "Malicious list loaded in graph"
  print "Nodes in graph", count
  return graph
  
def load_benign_graph(benign_list, graph):
  count = 0
  for line in benign_list:
    if line in graph:
      graph.node[line]['trust_state'] = +1
      count+=1
  print "Benign list loaded in graph"
  print "Nodes in graph", count
  return graph

def testing_in_graph(gr):
  var = raw_input("Training file:")
  var = var.rstrip()
  f1 = open(var,'r')
  var2 = raw_input("Testing file:")
  var2 = var2.rstrip()
  f2 = open(var2,'r')
  var3 = raw_input("New testing file:")
  var3 = var3.rstrip()
  f3 = open(var3,'w')
  gr2 = nx.Graph()
  for n in f2:
    if n in gr:
      gr2.add_node(n)
      gr2.node[n]['type'] = gr.node[n]['type']
      for e in gr.edge[n]:
        gr2.add_node(e)
        gr2.node[e]['type'] = gr.node[e]['type']
        for f in gr.edge[e]:
          gr2.add_node(f)
          gr2.node[f]['type'] = gr.node[f]['type']
# temp graph complete here
  for m in f1:
    m = m.rstrip()
    if m in gr2:
      f3.write("%s\n" %m)
  f3.close()
  f2.close()
  f1.close()
  gr2.clear()
  return gr

def graph_trust_nos(gr):
  ipnos = 0
  domains = 0
  ns = 0
  np = 0
  for n in gr:
    if gr.node[n]['type'] == "IPv4Address":
      if gr.node[n]['trust_state'] >= 1:
        ipnos+=1
    elif gr.node[n]['type'] == "DNSName":
      if gr.node[n]['trust_state'] >=1:
        domains+=1
    elif gr.node[n]['type'] == "NameServer":
      if gr.node[n]['trust_state'] >=1:
        ns+=1
    elif gr.node[n]['type'] == "IPv4Prefix":
      if gr.node[n]['trust_state'] >=1:
        np+=1
  print ipnos, "IPs" ,domains, "Domains", ns, "Nameservers", np, "Prefixes"

#rules_dict = {"1":ruleone,"2":ruletwo,"3":rulethree,"4":rulefour,"5":rulefive,"6":rulesix,"7":ruleseven, "r":rulefour_temp}

#rules_dict = {'1':ruleone,'2':ruletwo,'3':rulethree,'4':rulefour,'5':rulefive,'6':rulesix,'7':ruleseven, 'r':rulefour_temp} # mini str
def switch(rule):
  rules_dict = {1:ruleone,2:ruletwo,3:rulethree,4:rulefour,5:rulefive,6:rulesix,7:ruleseven, 8:ruleeight,9:rulenine} # int
  try:
    return rules_dict[int(rule)]
  except:
    print "Error in switching code"

def iterate(gr, rule):
#  rule = int(rule)
  temp = rule
  rfile = "r"+str(temp)+"_op"
  g = open(rfile,'w')
  print "here"
  print switch(rule)
  try:
    gr = switch(rule)(gr,g)
    g.close()
    return gr
  except:
    print "Error in Iterate switch"

# main starts here
def main():
  graphpath = sys.argv[1]
  gr = load_graph(graphpath)

  print " -------------------Usage python bwrapper.py graph ------------------"
  print "----------------------------------------------------------------------------------"
  print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
  print "Rule 2: Generate potential malicious DNSnames from malicious IPs"
  print "Rule 3: Generate potential malicious DNSnames from malicious Nameservers"
  print "Rule 4: Generate potential malicious IPs from malicious Prefixes"
  print "Rule 5: Probabilistic rule marking nameservers hosting %x(ratio) of malicious domain names"
  print "Rule 6: Probabilistic rule marking IPs hosting %x(ratio) of malicious domain names"
  print "Rule 7: Probabilistic rule marking prefix containing  %x(ratio) of malicious ips"
  print "----------------------------------------------------------------------------------"
  while True:
    try:
      choice = int(raw_input(" Individual rule testing(1), Verifying blacklists(2) or Exit(3): "))
      ct1 = 0 # number of entities in test file
      ct2 = 0 # number of them in the graph
      ct3 = 0 # number of them perfect mal - means trust=1 in the graph
      ct4 = 0 # number of them potential mal - means trust =2 in the graph
      ct5 = 0 # number of nodes in graph but with no previous trust information
      if choice == 2:
        f1 = str(raw_input("Enter Parent malicious file:  ")) 
        reset_graph_trust(gr)
        mal_list = load_mal(f1)
        gr2 = load_mal_graph(mal_list, gr)
        for i in range(1,8):
          gr2 = iterate(gr2,i) # Think about this
        f2 = str(raw_input("Verify blacklist service, enter the blacklist file name to check:  ")) 
        fd = open(f2,'r')
        ls = []
        for n in fd:
          n=n.rstrip()
          ls.append(n) 
          ct1+=1
          if n in gr2:
            ct2+=1   
            if gr2.node[n]['trust_state'] == 1:
              ct3+=1
            elif gr2.node[n]['trust_state'] == 2:
              ct4+=1
            else:
              ct5+=1
        print ct1, "total nodes in file"   
        print ct2, "total nodes in graph"
        print ct3, "Perfect malicious identified by child file"
        print ct4, "Potential malicious identified by child fle"
        print ct5, "No trust about these nodes, present in graph"
        vara =  ((float(ct3)/ct2)*100)
        varb = ((float(ct4)/ct2)*100)
        print vara, "% of mal nodes"
        print varb, "% of potential mal nodes"
        if vara >= 50 or varb >=50:
          vard = str(raw_input("Please enter the filename to save the blacklist verification information:" ))
          varc = open(vard, 'w')
          for i in ls: 
            print >>varc, i
          for n in gr:
            if gr.node[n]['trust_state'] == 1:
              print >>varc, n
        varc.close()
        print "File written"
        fd.close()
        print "Good luck"
      elif choice == 1:
        wrapper(gr)
      elif choice ==3:
        break
      else:
        print "Wrong Choice."
    except:
      print "Error in main script"
      pass

  
        
