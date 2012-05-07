#!/usr/bin/env python

import sys
var = []
f1 = open(sys.argv[1],'r')
for i in range(0,10):
    for j in range(0,3):
        var.append(f1.readline().rstrip())
    print ("%f %s %s %s\n" %((i+1)/10.0, var[0],var[1],var[2]))
    var = []
    i += 1
f1.close()
