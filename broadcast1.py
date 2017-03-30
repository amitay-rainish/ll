# -*- coding: utf-8 -*-
from scapy.all import *
import timeit
import time
import argparse

def go(dst):
    """
    locate the loactions
    """
    start2 = timeit.default_timer()
    srcsav = ""
    t = []
    ip = []
    for i in range(30):
        l1 = IP(ttl=i+1, dst=dst)/ICMP()
        start1 = timeit.default_timer()
        s = sr1(l1, verbose=0)
        end = timeit.default_timer()
        if s[IP].src == srcsav:
            break
        if end - start2 >= 14:
            break
        srcsav = s[IP].src
        ip.append(srcsav)
        t.append(end - start1)
    print "dst: %s overall time: %s  loactons: %s" % (dst, -(t[len(t)-1] - start2), len(ip))
    return t, ip


def main():
    """
    Add Documentation here
    """
    pass  # Replace Pass with Your Code
f = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="10.100.102.1")
f.show()
dst = "www.google.com"
f, ip = go(dst)
for i in ip:
    ar = srp1(f, verbose=0, timeout=20)
    print 90
    f = Ether(dst="ff:ff:ff:ff:ff:ff", src=ar[Ether].src)/ARP(op=1, pdst=i)
    print i
if __name__ == '__main__':
    main()