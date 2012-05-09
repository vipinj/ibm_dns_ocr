#!/usr/bin/env python
import sys
sys.path.append("/home/vipin/dnspaper/ip_dns/networkx/networkx-1.5rc1/")

import networkx as nx
import random
import time
import cPickle
import math

def close(f):
    "Closing file"
    f.flush()
    f.close()
#!/usr/bin/env python

def ingraph(gr,f):
    count = 0
    for line in f:
        line = line.rstrip()
        if line in gr:
            count += 1
        else:
            pass
    print count
        
def ingraph_write(gr,f,g):
    count = 0
    for line in f:
        line = line.rstrip()
        if line in gr:
            count += 1
            g.write("%s\n" %line)
        else:
            pass
    print count

def delete_node(gr):
    var = raw_input("Enter the node to delete: ")
    var = var.rstrip()
    if var in gr:
        gr.remove_node(var)
    else:
        pass

def write_graph(gr):
    var = raw_input("Please enter a filename to dump graph: ")
    var = var.rstrip()
    g = open(var, 'w')
    cPickle.dump(gr,g)
    g.close()

def read_graph():
    var = raw_input("Enter pickle file name: ")
    var = var.rstrip()
    f = open(var,'r')
    gr = cPickle.load(f)
    f.close()
    return gr

def query_graph(gr):
  while True:
    try:
      var = raw_input("Enter the domain/ip to be outputted:")
      var = var.rstrip()
      if var == "NO":
        break;
      elif var in gr:
        print gr.node[var]['type']
        for e in gr.edge[var]:
          print e,gr.node[e]['type']
          for f in gr.edge[e]:
            print "\t",f,gr.node[f]['type']
      else:
        print "Not found in graph"
  #    print gr.neighbors(var.rstrip())
    except:
      print "Error"
      pass
def query_graph_single(gr): # only first hop neighbors
  while True:
    try:
      var = raw_input("Enter the domain/ip to be outputted:")
      var = var.rstrip()
      if var == "NO":
        break;
      elif var in gr:
        print gr.node[var]['type'], len(gr.neighbors(var))
        for e in gr.edge[var]:
          print e,gr.node[e]['type']
      else:
        print "Not found in graph"
  #    print gr.neighbors(var.rstrip())
    except:
      print "Error"
      pass

def stats(gr):
    ips = 0
    doms =0
    ns = 0
    mx = 0
    prefix = 0
    unknown = 0
    for n in gr.nodes():
        if gr.node[n]['type'] =="IPv4Address":
            ips += 1
        elif gr.node[n]['type'] =="DNSName":
            doms+= 1
        elif gr.node[n]['type'] =="MailServer":
            mx += 1
        elif gr.node[n]['type'] =="NameServer":
            ns += 1
        elif gr.node[n]['type'] =="IPv4Prefix":
            prefix += 1
        else:
            unknown += 1
    print ips, doms, ns, mx, prefix, unknown
