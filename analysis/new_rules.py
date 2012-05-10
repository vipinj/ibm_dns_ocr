#!/usr/bin/env python
import sys
sys.path.append("/home/vipin/dnspaper/ip_dns/networkx/networkx-1.5rc1/")

import networkx as nx
import math
NEG_SC = -0.8 # from tpfp analysis, these provide better numbers, high tp, medium fp
POS_SC = 0.6
# def wrapper(gr):
#   print "----------------------------------------------------------------------------------"
#   print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
#   print "Rule 2: Generate potential malicious Dnsnames from malicious IPs"
#   print "Rule 3: Generate potential malicious MailServers from malicious IPs"
#   print "Rule 4: Generate potential malicious Dnsnames from malicious Nameservers"
#   print "Rule 5: Generate potential malicious IPs from malicious Prefixes"
#   print "Rule 6: Probabilistic rule marking nameservers hosting %x of malicious domain names"
#   print "Rule 7: Probabilistic rule marking IPs containing  %x of malicious domain names"
#   print "Rule 8: Probabilistic rule marking malicious prefix containing  %x of malicious ips"
#   print "Rule 9: Generate potential malicious mailservers from malicious domains"
#   print "----------------------------------------------------------------------------------"
#   counter = 0
#   try:
#     while True:
#       r1 = raw_input("Enter a rule? (y/n/clear) : ")
#       counter += 1
#       if r1 == 'n': 
#         print "Exit."
#         break 
#       elif r1.rstrip() == "clear":
#         reset_graph_trust(gr)
#       else:
#         if counter == 1:
#           reset_graph_trust(gr)
#         rule = raw_input("Please Enter the rule({1-4} or {5-7): ")
#         malf = str(raw_input("Please Enter the malicious filename: "))
#         mal_list = load_mal(malf)
#         gr = load_mal_graph(mal_list, gr)
#         benignf = str(raw_input("Please Enter the benign filename: "))
#         benign_list = load_mal(benignf)
#         gr = load_benign_graph(benign_list, gr)
#         gr = iterate(gr, rule)
#   except:
#     print "Error applying more rules"
#     pass
#End of wrapper() ###########    
# Mark nameservers malicious if they are hosted on a malicious IP
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
        elif graph.node[n]['trust_state'] == +1:
          for e in graph.edge[n]:
            try:
              if graph.edge[n][e]['type'] == "A":
                 # Nameservers are appended with a . at the end, for e.g. ns1.google.com. is a NS, not a domain (ns1.google.com)
                temp = e + "."
                if temp in graph:
                  print >>g, ("NameServer %s is possibly benign because it is hosted at %s" % (e,n))
                  if graph.node[temp]['trust_state'] == 0:
                    graph.node[temp]['trust_state'] = 1
                  else:
                    graph.node[temp]['trust_state'] = 1 + graph.node[temp]['trust_state']
            except KeyError:
              print "No type on edge %s - %s" % (e,n)
        else:
          pass
      except:
        print "Error in trust state code ?"
  return graph
# Mark domains mailicious if they are hosted on a malicious IP Address - maliciousness = -1/degree(neighbors)
# The division in maliciousness is because domains are dime a dozen
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
      elif graph.node[n]['trust_state'] == 1:
        pm = float(1)/graph.degree(n) # Each neighbor node gets a score divided by the degree
        for e in graph.edge[n]:
          # Names hosted at a malicious IP are potential malicious
          try:
            if graph.edge[n][e]['type'] == "A":
              print >>g, ("Name %s is possibly benign because it is hosted at %s" % (e,n))
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
  return graph
# Mark mailservers as malicious if hosted on malicious IPs
def rulethree(graph,g):
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Address":
      if graph.node[n]['trust_state'] == -1:
        for e in graph.edge[n]:
          try:
            if graph.edge[n][e]['type'] == "MX":
              if graph.node[e]['trust_state'] == 0:
                graph.node[e]['trust_state'] = -1
                print >>g, ("Mailserver %s is possibly malicious because it is hosted at %s" % (e,n))
              else:
                graph.node[e]['trust_state'] = -1 + graph.node[e]['trust_state']
          except KeyError:
            print "No type on edge %s - %s" % (e,n)
      elif graph.node[n]['trust_state'] == 1:
        for e in graph.edge[n]:
          try:
            if graph.edge[n][e]['type'] == "MX":
              if graph.node[e]['trust_state'] == 0:
                print >>g, ("Mailserver %s is possibly malicious benign it is hosted at %s" % (e,n))
                graph.node[e]['trust_state'] = 1
              else:
                graph.node[e]['trust_state'] = 1 + graph.node[e]['trust_state']
          except KeyError:
            print "No type on edge %s - %s" % (e,n)
      else:
        pass
    else:
      pass
  return graph

# Marking names malicious due to a malicious mail server will be covered in ruletwo
# Marking names malicious due to a malicious name server
def rulefour(graph,g):
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
      elif graph.node[n]['type'] == "NameServer":
#        if len(gr.neighbors(n)) >= 5:
        if graph.node[n]['trust_state'] == 1:
          pm = float(1)/graph.degree(n) # Each neighbor node gets a score divided by the degree
          for e in graph.edge[n]:
              # Names resolved by a malicious NameServer are potential malicious
            print >>g, ("Name %s is possibly benign because it is resolved by %s" % (e,n))
            if graph.node[e]['trust_state'] == 0:
              graph.node[e]['trust_state'] = pm
            else:
              graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
    except KeyError:
      print "No type on edge %s - %s" % (e,n)
  return graph
# Marking IPs malicious due to a malicious Prefix
def rulefive(graph,g):
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "IPv4Prefix":
        if graph.node[n]["trust_state"] == -1:
          pm = -float(1)/graph.degree(n)
          for e in graph.edge[n]:
            print >> g, ("IP %s is malicious as it is presented in the malicious Prefix %s\n" %(e,n))
            if graph.node[e]['trust_state'] == 0:
              graph.node[e]['trust_state'] = pm
            else:
              graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
      elif graph.node[n]['type'] == "IPv4Prefix":
        if graph.node[n]["trust_state"] == 1:
          pm = float(1)/graph.degree(n)
          for e in graph.edge[n]:
            print >> g, ("IP %s is benign as it is presented in the malicious Prefix %s\n" %(e,n))
            if graph.node[e]['trust_state'] == 0:
              graph.node[e]['trust_state'] = pm
            else:
              graph.node[e]['trust_state'] = graph.node[e]['trust_state'] + pm
    except KeyError:
      print "No type on edge %s - %s" %(e,n)
  return graph

      
# Marking nameserver malicious due to a bad domain neighborhood
def rulesix(graph,g,POS_SC,NEG_SC):
  h = open("r6_op_condensed",'w')  
#  p2 = float(raw_input("Please enter the ratio: "))
  p2 = 0.5
#  p2 = 0.4
#  print "Ratio: ", p2
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "NameServer":
        if graph.node[n]['trust_state'] != -1:
          allnodes = 0.0
          malnodes = 0.0
          malscore = 0.0
          npos = 0
          pos_score = 0
          neg_score = 0
          for e in graph.edge[n]:
            neigh_num = len(graph.neighbors(e))
            negnum = neigh_num * NEG_SC
            posnum = neigh_num * POS_SC
            if graph.node[e]['type'] == "DNSName":
              allnodes += 1
#              if graph.node[e]['trust_state'] > negnum: # ERROR
              if graph.node[e]['trust_state'] > posnum:
                npos += 1
                pos_score += graph.node[e]['trust_state']
#              elif graph.node[e]['trust_state'] < posnum:  #ERROR
              elif graph.node[e]['trust_state'] < negnum:
#          malscore += graph.node[e]['trust_state'] # Irrespective of +ve/-ve, if n(+ve) 
                malnodes += 1 
                neg_score += graph.node[e]['trust_state']
              else:
                pass
          if allnodes == 0:
            continue
          if float(malnodes)/allnodes > p2:
            neg_score += -1 # We give this score because, its beyond our ratio
            if malnodes > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          elif float(malnodes)/allnodes < p2:
            pos_score += 1 # We give this score because, its beyond our ratio
            if malnodes > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
#          print n,graph.node[n]['trust_state']
          if graph.node[n]['trust_state'] < -1 and malnodes > 1:
            h.write("%s - Score: %f NameServer (domains) Total: %d Malicious: %d -%f %% \n" %(n, graph.node[n]['trust_state'], allnodes, malnodes, ((float(malnodes)/allnodes)*100)))
    except KeyError:
      print  "No type on edge %s - %s" % (e,n)
  return graph
# Marking IP as malicious due to a bad neighborhood of domains
def ruleseven(graph,g,POS_SC,NEG_SC):
#  p1 = float(raw_input("Please enter the ratio: "))
#  print "Ratio: ", p1
#  p1 = 0.4
  p1 = 0.5
  h = open("r7_op_condensed",'w')
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Address":
      if graph.node[n]['trust_state'] != -1:
        arecs = 0.0
        mal_arecs = 0.0
        npos = 0
        neg_score = 0.0
        pos_score = 0.0
        for e in graph.edge[n]:
          neigh_num = len(graph.neighbors(e))
          negnum = neigh_num * NEG_SC
          posnum = neigh_num * POS_SC
          if graph.edge[n][e]['type'] == 'A':
            arecs += 1
            if graph.node[e]['trust_state'] < negnum:
              mal_arecs += 1
              neg_score += graph.node[e]['trust_state']
            elif graph.node[e]['trust_state'] > posnum:
              npos += 1
              pos_score += graph.node[e]['trust_state']
            else:
              pass
        if arecs == 0:
          continue
        try:
          if (float(mal_arecs)/arecs) > p1:
            neg_score += -1 # We give this score because, its beyond our ratio
            if mal_arecs > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          elif (float(mal_arecs)/arecs) < p1:
            pos_score += 1 # We give this score because, its beyond our ratio
            if mal_arecs > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
        except KeyError:
          print  "No type on edge %s - %s" % (e,n)
        if mal_arecs >= 10:
          h.write("%s - Score: %f Domains Total: %d Malicious: %d -%f %% \n" %(n, graph.node[n]['trust_state'], arecs, mal_arecs, ((float(mal_arecs)/arecs)*100)))
#      print arecs
  return graph


# Marking prefix as malicious as it lies in a bad ip neighborhood
def ruleeight(graph,g,POS_SC,NEG_SC):
#  p3 = float(raw_input("Please enter the ratio:"))
#  print "Ratio: ", p3
  p5 = 0.9
#  p5 = 0.9
  h = open("r8_op_condensed",'w')
  for n in graph.nodes():
    if graph.node[n]['type'] == "IPv4Prefix":
      if graph.node[n]["trust_state"] == 0:
        allnodes = 0.0
        malnodes = 0.0
        npos = 0
        pos_score = 0.0
        neg_score = 0.0
        for e in graph.edge[n]:
          neigh_num = len(graph.neighbors(e))
          negnum = neigh_num * NEG_SC
          posnum = neigh_num * POS_SC
          allnodes += 1
          if graph.node[e]['trust_state'] < negnum:
            malnodes += 1
            neg_score += graph.node[e]['trust_state']
          elif graph.node[e]['trust_state'] > posnum:
            npos += 1
            pos_score += graph.node[e]['trust_state']
          else:
            pass
        try:
          if(float(malnodes)/allnodes) > p5:
            neg_score += -1  
            if malnodes > npos:
              neg_score += -1
            else:
              pos_score += 1
          elif(float(malnodes)/allnodes) < p5:
            pos_score += 1  
            if malnodes > npos:
              neg_score += -1
            else:
              pos_score += 1
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
          h.write("%s - Score: %f Prefix (IPs) Total: %d Malicious: %d -%f %%\n" %(n, graph.node[n]['trust_state'], allnodes, malnodes, ((float(malnodes)/allnodes)*100)))
  return graph
# Marking names malicious as it lies on a bad mailserver
def rulenine(graph,g,POS_SC,NEG_SC):
#  p4 = float(raw_input("Please enter the ratio:"))
#  print "Ratio: ", p4
  p4 = 0.9
#  p4 = p
  h = open("r9_op_condensed",'w')
  for n in graph.nodes():
    try:
      if graph.node[n]['type'] == "MailServer":
        if graph.node[n]["trust_state"] == 0:
          allnodes = 0.0
          malnodes = 0.0
          npos = 0
          pos_score = 0.0
          neg_score = 0.0
          for e in graph.edge[n]:
            neigh_num = len(graph.neighbors(e))
            negnum = neigh_num * NEG_SC
            posnum = neigh_num * POS_SC
            allnodes += 1
            if graph.node[e]['trust_state'] < negnum: # Do we not need to check an 'MX' 
              malnodes += 1
              neg_score += graph.node[e]['trust_state']
            elif graph.node[e]['trust_state'] > posnum:
              npos += 1
              pos_score += graph.node[e]['trust_state']
            else:
              pass
          if float(malnodes)/allnodes > p4:
            neg_score += -1 # We give this score because, its beyond our ratio
            if malnodes > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          elif float(malnodes)/allnodes < p4:
            pos_score += 1 # We give this score because, its beyond our ratio
            if malnodes > npos:
              neg_score += -1 # We give this one because, malicious nodes are more than benign nodes
            else:
              pos_score += 1 # For benignity of the node
          else:
            pass
          if math.fabs(neg_score) > pos_score :
            graph.node[n]['trust_state'] = neg_score
          elif  math.fabs(neg_score) < pos_score :
            graph.node[n]['trust_state'] = pos_score
          else:
            graph.node[n]['trust_state'] = pos_score + neg_score # What else can it be 
          if malnodes >= 10: # simply for the purposes of numbers
            h.write("%s - Score: %f MailServer (domains) Total: %d Malicious: %d -%f %% \n" %(n, graph.node[n]['trust_state'], allnodes, malnodes, ((float(malnodes)/allnodes)*100)))
    except KeyError:
      print  "No type on edge %s - %s" % (e,n)
  return graph
    
def propagate(gr):
  print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
  print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
  print "Rule 2: Generate potential malicious DNSnames from malicious IPs"
  print "Rule 3: Generate potential malicious MailServers from malicious IPs"
  print "Rule 4: Generate potential malicious DNSnames from malicious Nameservers"
  print "Rule 5: Generate potential malicious IPs from malicious Prefixes"
  print "Rule 6: Probabilistic rule marking nameservers hosting %x(ratio) of malicious domain names"
  print "Rule 7: Probabilistic rule marking IPs hosting %x(ratio) of malicious domain names"
  print "Rule 8: Probabilistic rule marking prefix containing  %x(ratio) of malicious ips"
  print "Rule 9: Probabilistic rule marking mailservers from malicious DNSnames" 
  print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
  mald = raw_input("Enter the training domain file: ")
  mali = raw_input("Enter the training IP file: ")
  benignf = str(raw_input("Please Enter the benign filename: "))
# #  var = raw_input("Enter the testing domain file")
#   var1= var1.rstrip()
#   var2= var2.rstrip()
  choice = raw_input("Do you want to reset the graph: ")
  choice = choice.rstrip()
  if choice:
    reset_graph_trust(gr)
  else:
    pass
  mal_list = load_mal(mald)
  gr = load_mal_graph(mal_list, gr)
  mal_list2 = load_mal(mali)
  gr = load_mal_graph(mal_list2, gr)
  benign_list = load_benign(benignf)
  gr = load_benign_graph(benign_list, gr)
  for i in range(1,9):
    iterate(gr,i)
# Test without rule nine, as it takes a lot of time
    
def dump_graph(gr):
  var = raw_input("Please enter a filename to dump graph: ")
  var = var.rstrip()
  f = open(var,'w')
  cPickle.dump(gr,f)
  f.close()
  print "Graph dumped to disk"

def dump_mal(gr):
  var = raw_input("Please enter a filename to dump potentially malicious nodes : ")
  var = var.rstrip()
  f = open(var,'w')
  for n in gr.nodes():
    if gr.node[n]['trust_state'] < 0:
      f.write("%s %f" %(n, gr.node[n]['trust_state']))
  f.close()  
  
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
      graph.node[line]['trust_state'] = +10
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

# def graph_trust_nos(gr):
#   neg_ip = 0
#   pos_ip = 0
#   neu_ip = 0 # neutral
#   neg_dom = 0
#   pos_dom = 0
#   neu_dom = 0
#   neg_ns = 0
#   pos_ns = 0
#   neu_ns = 0
#   neg_ipp = 0
#   pos_ipp = 0
#   neu_ipp = 0
#   neg_mx = 0
#   pos_mx = 0
#   neu_mx = 0
#   for n in gr:
#     if gr.node[n]['type'] == "IPv4Address":
#       if gr.node[n]['trust_state'] < 0:
#         neg_ip += 1
#       elif gr.node[n]['trust_state'] > 0: 
#         pos_ip += 1
#       else:
#         neu_ip += 1
#     elif gr.node[n]['type'] == "DNSName":
#       if gr.node[n]['trust_state'] < 0:
#         neg_dom += 1
#       elif gr.node[n]['trust_state'] > 0: 
#         pos_dom += 1
#       else:
#         neu_dom += 1
#     elif gr.node[n]['type'] == "NameServer":
#       if gr.node[n]['trust_state'] < 0:
#         neg_ns += 1
#       elif gr.node[n]['trust_state'] > 0: 
#         pos_ns += 1
#       else:
#         neu_ns += 1
#     elif gr.node[n]['type'] == "MailServer":
#       if gr.node[n]['trust_state'] < 0:
#         neg_mx += 1
#       elif gr.node[n]['trust_state'] > 0: 
#         pos_mx += 1
#       else:
#         neu_mx += 1        
#     elif gr.node[n]['type'] == "IPv4Prefix":
#       if gr.node[n]['trust_state'] < 0:
#         neg_ipp += 1
#       elif gr.node[n]['trust_state'] > 0: 
#         pos_ipp += 1
#       else:
#         neu_ipp += 1        
#   print "Negatives(malicious) Ips:%d, domains:%d, NS:%d, MX:%d, Prefixes:%d\n" %(neg_ip, neg_dom, neg_ns, neg_mx, neg_ipp)
#   print "Positives(benign) Ips:%d, domains:%d, NS:%d, MX:%d, Prefixes:%d\n" %(pos_ip, pos_dom, pos_ns, pos_mx, pos_ipp)
#   print "Neutral Ips:%d, domains:%d, NS:%d, MX:%d, Prefixes:%d\n" %(neu_ip, neu_dom, neu_ns, neu_mx, neu_ipp)

def switch(rule):
  rules_dict = {1:ruleone,2:ruletwo,3:rulethree,4:rulefour,5:rulefive,6:rulesix,7:ruleseven, 8:ruleeight,9:rulenine} # int
  try:
    return rules_dict[int(rule)]
  except:
    print "Error in switching code"

def iterate(gr, rule,POS_SC,NEG_SC):
#  rule = int(rule)
  temp = rule
  rfile = "r"+str(temp)+"_op"
  g = open(rfile,'w')
#  print "here"
  print switch(rule)
  try:
    if int(rule) >= 6 and int(rule) <=9:
      gr = switch(rule)(gr,g,POS_SC,NEG_SC)
    else:
      gr = switch(rule)(gr,g)
#    if int(rule) == 6:
#      gr = switch(rule)(gr,g,p)
    g.close()
    return gr
  except:
    print "Error in Iterate switch"

# # main starts here
# def main():
#   graphpath = sys.argv[1]
#   gr = load_graph(graphpath)

#   print " -------------------Usage python bwrapper.py graph ------------------"
#   print "----------------------------------------------------------------------------------"
#   print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
#   print "Rule 2: Generate potential malicious DNSnames from malicious IPs"
#   print "Rule 3: Generate potential malicious DNSnames from malicious Nameservers"
#   print "Rule 4: Generate potential malicious IPs from malicious Prefixes"
#   print "Rule 5: Probabilistic rule marking nameservers hosting %x(ratio) of malicious domain names"
#   print "Rule 6: Probabilistic rule marking IPs hosting %x(ratio) of malicious domain names"
#   print "Rule 7: Probabilistic rule marking prefix containing  %x(ratio) of malicious ips"
#   print "----------------------------------------------------------------------------------"
#   while True:
#     try:
#       choice = int(raw_input(" Individual rule testing(1), Verifying blacklists(2) or Exit(3): "))
#       ct1 = 0 # number of entities in test file
#       ct2 = 0 # number of them in the graph
#       ct3 = 0 # number of them perfect mal - means trust=1 in the graph
#       ct4 = 0 # number of them potential mal - means trust =2 in the graph
#       ct5 = 0 # number of nodes in graph but with no previous trust information
#       if choice == 2:
#         f1 = str(raw_input("Enter Parent malicious file:  ")) 
#         reset_graph_trust(gr)
#         mal_list = load_mal(f1)
#         gr2 = load_mal_graph(mal_list, gr)
#         for i in range(1,8):
#           gr2 = iterate(gr2,i) # Think about this
#         f2 = str(raw_input("Verify blacklist service, enter the blacklist file name to check:  ")) 
#         fd = open(f2,'r')
#         ls = []
#         for n in fd:
#           n=n.rstrip()
#           ls.append(n) 
#           ct1+=1
#           if n in gr2:
#             ct2+=1   
#             if gr2.node[n]['trust_state'] == 1:
#               ct3+=1
#             elif gr2.node[n]['trust_state'] == 2:
#               ct4+=1
#             else:
#               ct5+=1
#         print ct1, "total nodes in file"   
#         print ct2, "total nodes in graph"
#         print ct3, "Perfect malicious identified by child file"
#         print ct4, "Potential malicious identified by child fle"
#         print ct5, "No trust about these nodes, present in graph"
#         vara =  ((float(ct3)/ct2)*100)
#         varb = ((float(ct4)/ct2)*100)
#         print vara, "% of mal nodes"
#         print varb, "% of potential mal nodes"
#         if vara >= 50 or varb >=50:
#           vard = str(raw_input("Please enter the filename to save the blacklist verification information:" ))
#           varc = open(vard, 'w')
#           for i in ls: 
#             print >>varc, i
#           for n in gr:
#             if gr.node[n]['trust_state'] == 1:
#               print >>varc, n
#         varc.close()
#         print "File written"
#         fd.close()
#         print "Good luck"
#       elif choice == 1:
#         wrapper(gr)
#       elif choice ==3:
#         break
#       else:
#         print "Wrong Choice."
#     except:
#       print "Error in main script"
#       pass

# def bl_propagate(gr, mald):
#   print "Processing All the rules, Stand back: " # There might be a hurricane coming
#   print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
#   print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
#   print "Rule 2: Generate potential malicious DNSnames from malicious IPs"
#   print "Rule 3: Generate potential malicious MailServers from malicious IPs"
#   print "Rule 4: Generate potential malicious DNSnames from malicious Nameservers"
#   print "Rule 5: Generate potential malicious IPs from malicious Prefixes"
#   print "Rule 6: Probabilistic rule marking nameservers hosting %x(ratio) of malicious domain names"
#   print "Rule 7: Probabilistic rule marking IPs hosting %x(ratio) of malicious domain names"
#   print "Rule 8: Probabilistic rule marking prefix containing  %x(ratio) of malicious ips"
#   print "Rule 9: Probabilistic rule marking mailservers from malicious DNSnames" 
#   print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
#   # mald = raw_input("Enter the training domain file: ")
#   # mali = raw_input("Enter the training IP file: ")
#   # benignf = str(raw_input("Please Enter the benign filename: "))
# # #  var = raw_input("Enter the testing domain file")
# #   var1= var1.rstrip()
# #   var2= var2.rstrip()

#   mal_list = load_mal(mald)
#   gr = load_mal_graph(mal_list, gr)
#   mali = "bl_ip_list"
#   mal_list2 = load_mal(mali)
#   gr = load_mal_graph(mal_list2, gr)
#   benignf = "benign50k"
#   benign_list = load_benign(benignf)
#   gr = load_benign_graph(benign_list, gr)
#   for i in range(1,10):
#     iterate(gr,i)
#   ret = {}
#   for i in gr.nodes():
#     if gr.node[i]['trust_state'] < 0:
#       ret[i] = gr.node[i]['trust_state']
#   return ret
      
def bl_propagate2(gr, mald,malip,num,POS_SC,NEG_SC):
  print "Processing All the rules, Stand back: " # There might be a hurricane coming
  print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
  print "Rule 1: Generate potential malicious Nameservers from malicious IPs"
  print "Rule 2: Generate potential malicious DNSnames from malicious IPs"
  print "Rule 3: Generate potential malicious MailServers from malicious IPs"
  print "Rule 4: Generate potential malicious DNSnames from malicious Nameservers"
  print "Rule 5: Generate potential malicious IPs from malicious Prefixes"
  print "Rule 6: Probabilistic rule marking nameservers hosting %x(ratio) of malicious domain names"
  print "Rule 7: Probabilistic rule marking IPs hosting %x(ratio) of malicious domain names"
  print "Rule 8: Probabilistic rule marking prefix containing  %x(ratio) of malicious ips"
  print "Rule 9: Probabilistic rule marking mailservers from malicious DNSnames" 
  print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
  # mald = raw_input("Enter the training domain file: ")
  # mali = raw_input("Enter the training IP file: ")
  # benignf = str(raw_input("Please Enter the benign filename: "))
# #  var = raw_input("Enter the testing domain file")
#   var1= var1.rstrip()
#   var2= var2.rstrip()
  mal_list = {}
  mal_list2 = {}

  for ln in mald:
    ln = ln.rstrip()
    mal_list[ln] = 1


  for ln in malip:
    ln = ln.rstrip()
    mal_list2[ln] = 1

  if not num:
    reset_graph_trust(gr)
  else: 
    pass

#  mal_list = load_mal(mald)
  gr = load_mal_graph(mal_list, gr)
#   mali = malip
#   mal_list2 = load_mal(mali)
  gr = load_mal_graph(mal_list2, gr)

  benignf = "benign50k" # local benign file
  benign_list = load_benign(benignf)
  gr = load_benign_graph(benign_list, gr)
# hold on rule 9 as it takes a lot of time
  for i in range(1,9):
    iterate(gr,i,POS_SC,NEG_SC)
  ret = {}
  for i in gr.nodes():
    if gr.node[i]['trust_state'] != 0:
      ret[i] = gr.node[i]['trust_state']
  return ret
