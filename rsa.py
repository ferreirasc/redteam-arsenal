# Given n and e, decrypt the cipher

import sys,math
from binascii import unhexlify

cipher = [309117097659990665453,
125675338953457551017,
524099092120785248852,
772538252438953530955,
547462544172248492882,
28215860448757441963,
543018082275730030658,
585936545563088067075,
131807465077304821584]
n = 783340156742833416191
e = 653
p = 27789079547 #http://www.numberempire.com/numberfactorizer.php
q = 28188776653 #http://www.numberempire.com/numberfactorizer.php

def bezout(a, b):
	if a == 0 and b == 0: 
		return (0, 0, 0)
	if b == 0: 
		return (a/abs(a), 0, abs(a))
	(u, v, p) = bezout(b, a%b)
	return (v, (u - v*(a/b)), p)
	
def inv_modulo(x, m):
	(u, _, p) = bezout(x, m)
	if p == 1: 
		return u%abs(m)
	else: 
		raise Exception("%s et %s ne sont pas premiers entre eux" % (x, m))

if __name__ == "__main__":
	phi = (p-1)*(q-1)
	d = inv_modulo(e,phi)
	m = ''.join([unhexlify(hex(pow(i,d,n))[2:-1]) for i in cipher])
	print m
	
	
