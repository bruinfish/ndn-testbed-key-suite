#!/usr/bin/env python

import argparse
import os
import hashlib
import pyccn
from pyccn import CCN, Key, Name
from M2Crypto import X509


###
os_info = os.uname()

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""  The script performs the following operations:
    - reads public key <key_file>,
    - creates content object with name <prefix-of-published-key>/%C1.M.K<sha256(key-bits)>/<version>/<segment>
    - signs it with key <path-to-signing-key-direcotry>/.ccnx_keystore
    - puts KeyLocator: <prefix-of-signing-key>/%C1.M.K<sha256(signing-key-bits)>
    - publishes content object to local repo
    - writes a pub_cert file for the key owner that contains the key and info objects""")

parser.add_argument("-i", "--identity", 
                    required=True, 
                    metavar="identity", 
                    help="specify the real-world identity of the key owner")
parser.add_argument("-a", "--affiliation", 
                    required=True, 
                    metavar="affiliation", 
                    help="specify the affiliation of the key owner")
parser.add_argument("-f", "--keyfile", 
                    required=True, 
                    metavar="key_file", 
                    help="specify the public key file")
parser.add_argument("-p", "--keyprefix", 
                    required=True, 
                    metavar="prefix-of-published-key", 
                    help="specify the key name prefix")
parser.add_argument("-F", "--keystorepath", 
                    required=True, 
                    metavar="path-to-signing-key-direcotry", 
                    help="specify the path to the keystore (directory that contains .ccnx_keystore file). Keystore password can be defined through CCNX_KEYSTORE_PASSWORD environment variable")
group = parser.add_mutually_exclusive_group()
group.add_argument("-P", "--signkeyprefix", 
                    metavar="prefix-of-signing-key", 
                    help="specify the name prefix of signing public key (or \"self\" for self-signed key)")
group.add_argument("-C", "--signkeycert",
                   metavar="cert-of-signing-key",
                   help="specify the cert file of signing key")
group.add_argument("-v", "--version",
                   metavar="version-of-signing-key",
                   help="specify the cert file of signing key")
parser.add_argument("-x", "--validity", 
                    required=True, 
                    type=int,
                    metavar="validity_period", 
                    help="specify the validity period in days")
parser.add_argument("-o", "--cert", 
                    metavar="pub_cert", 
                    help="specify the pub_cert file for the key owner (without suffix); default replacing key_file's suffix with \".pubcert\"")


args = parser.parse_args()




class RepoWriteClosure (pyccn.Closure):
    def upcall(self, kind, upcallInfo):
        if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            return pyccn.RESULT_OK;

        elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
            return pyccn.RESULT_REEXPRESS

        return pyccn.RESULT_OK

class PubKeyClosure (pyccn.Closure):
    def upcall(self, kind, upcallInfo):
        if kind == pyccn.UPCALL_INTEREST:
            interest = upcallInfo.Interest

            sys.stderr.write("<< PyCCN %s\n" % interest.name)

            co = pyccn.ContentObject (name=interest.name, content=self.keyBits, 
                                      signed_info=pyccn.SignedInfo (key_digest=handler.getDefaultKey ().publicKeyID, freshness=5))
            co.sign (handler.getDefaultKey ())

            handler.put (co)

        return pyccn.RESULT_OK

from publish import KeyPublisher

kp = KeyPublisher(args)
kp.init()
kp.show()
