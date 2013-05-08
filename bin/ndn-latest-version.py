#!/usr/bin/env python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"
    exit(1)

NDN_rootKeySha256 = "\xA7\xD9\x8B\x81\xDE\x13\xFCV\xC5\xA6\x92\xB4D\x93nVp\x9DRop\xED9\xEF\xB5\xE2\x03\x29\xA5S\x3Eh"
NDN_root = str(pyccn.Name ("/ndn/keys/").append ("\xC1.M.K\x00" + NDN_rootKeySha256).append ("\xFD\x01\x00P\x81\xBB\x3D").append("\x00"))

import argparse

parser = argparse.ArgumentParser(description='Get the latest version of key in use')
parser.add_argument('-p', '--keyprefix', metavar='NDN-prefix', type=str,
                    help='''Key namespace or key name (e.g., /ndn/keys)''')
parser.add_argument('-q', '--quiet', dest='verbose', action='store_false', default=True,
                    help='''Quiet mode (verify keys without printing out certification chains)''')
parser.add_argument('-s', '--scope', dest='scope', action='store', type=int, default=None,
                    help='''Set scope for enumeration and verification (default no scope)''')
parser.add_argument('-t', '--timeout', dest='timeout', action='store', type=float, default=0.1,
                    help='''Maximum timeout for each fetching operation/Interest lifetime (default: 0.1s)''')
group = parser.add_mutually_exclusive_group()
group.add_argument('-k', '--keyfile', dest='keyfile', action='store', type=str,
                   help='''Key file (PEM)''')
group.add_argument('-H', '--keyhash', dest='keyhash', action='store', type=str,
                   help='''Key hash (without marker, i.e.,  %%C1.M.K%%00)''')
group.add_argument('-c', '--keycert', dest='keycert', action='store', type=str,
                   help='''Key cert file provided by operators''')

from ndn_keys import simpleVerify

if __name__ == '__main__':
    args = parser.parse_args()
    if not args.keyprefix and not args.keycert:
        parser.print_help ()
        exit (1)
        
    args.check_meta = True
    args.verify = False

    sv = simpleVerify.SimpleVerify (args)
    sv.getCorrectVersion()
