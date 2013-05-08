#!/usr/bin/env python

import sys
import os
import re
import os.path as path
import argparse


def load_conf(file, conf):
    f = open(file, 'r')
    for line in f:
        if re.match(r'#', line):
            continue

        if re.match(r'\s*\n', line):
            continue

        (key, d, value) = line.rstrip('\n').partition('=')
        conf[key]=value.rstrip('"').lstrip('"')
    


conf = {}

dir = path.dirname(sys.argv[0])
script = path.basename(sys.argv[0])

if path.exists(dir + "/site-config"):
    load_conf(dir+"/site-config", conf)
else:
    sys.stderr.write("Please configure your site's parameters in [site-config]\n")
    sys.exit(1)

if conf['AFFI'] == "":
    sys.stderr.write("AFFI variable is not configured in [site-config]")
    sys.exit(1)

if conf['VALID_DAYS'] == "":
    sys.stderr.write("VALID_DAYS variable is not configured in [site-config]")
    sys.exit(1)

if conf['KEY_PREFIX'] == "":
    sys.stderr.write("KEY_PREFIX variable is not configured in [site-config]")
    sys.exit(1)

if 'SIGNING_KEY_NAME' not in os.environ or os.environ['SIGNING_KEY_NAME'] == "":
    conf['SIGNING_KEY_NAME'] = "/ndn/keys/ucla.edu"
else:
    conf['SIGNING_KEY_NAME'] = os.environ['SIGNING_KEY_NAME']

conf['KEYSTORE'] = dir + "/site-keystore/"
conf['CERTS'] = dir + "/certs/"
conf['SIGNED_CERTS'] = dir + "/signed-certs/"

conf['SYNC_TOPO_PREFIX'] = "/ndn/broadcast/sync/keys"
conf['SYNC_NAME_PREFIX'] = "/ndn/keys"

parser = argparse.ArgumentParser(description='Sign user public keys.')
arg_group = parser.add_mutually_exclusive_group()
arg_group.add_argument('-S', '--signkey',
                    action="store_true",
                    help="sign and publish user public keys (*.pem) located in "+conf['CERTS']+" folder")
arg_group.add_argument('-s', '--startsync',
                    action="store_true",
                    help="create sync slice and exit")

args = parser.parse_args()

if args.signkey:
    print "Sign Key"
elif args.startsync:
    print "Create Slice"
else:
    sys.stderr.write("Should Never Be Here!\n")
