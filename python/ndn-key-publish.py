#!/usr/bin/env python

import argparse
import os
import hashlib
from pycnn import CCN, Key, Name
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
parser.add_argument("-P", "--signkeyprefix", 
                    required=True, 
                    metavar="prefix-of-signing-key", 
                    help="specify the name prefix of signing public key (or \"self\" for self-signed key)")
parser.add_argument("-x", "--validity", 
                    required=True, 
                    type=int,
                    metavar="validity_period", 
                    help="specify the validity period in days")
parser.add_argument("-o", "--cert", 
                    metavar="pub_cert", 
                    help="specify the pub_cert file for the key owner (without suffix); default replacing key_file's suffix with \".pubcert\"")


nargs = parser.parse_args()

args = nargs

if os.path.isfile(args.keyfile):
    sys.stderr.write("Cannot open key file " + args.keyfile + "\n")
    sys.exit(1)

if os.path.isdir(args.keystorepath):
    sys.stderr.write("-F should specify directory where .ccnx_keystore file is located\n")
    sys.exit(1)

if args.cert = None:
    base_name = os.path.splitext(args.keyfile)
    cert = basename + ".pubcert"
else:
    cert = args.cert + ".pubcert"


handler = CCN()


key_der = X509.load_cert(args.keyfile, X509.FORMAT_PEM).get_pubkey().as_der()
pub_key = Key()
pub_key.fromDER(public=key_der)

k_name = Name(args.keyprefix).appendKeyID(pub_key).appendVersion()
repo_w_name = k_name.append('\xC1.R.sw').appendNonce()
repo_w_interest = pyccn.Interest (scope=1, interestLifetime=2)

i_name = 
valid_to = int(time.time() + 0.5 + args.validity*24*3600)
i_data = "<Meta><Name>" + args.identity + "</Name><Affiliation>" + args.identity + "</Affiliation><Valid_to>" + str(valid_to) + "</Valid_to></Meta>" 

old_home = os.environ['HOME']
os.environ['HOME'] = args.keystorepath

sk_name = Name(args.signkeyprefix)



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

repo_w_closure = RepoWriteClosure()
pubKey_closure = PubKeyClosure()
pubKey_closure.keyBits = key_der
pubKey_closure.signInfo = 

handler.setInterestFilter (k_name.appendSegment(0), pubKey_closure)

handler.expressInterest (repo_w_name, repo_w_closure, repo_w_interest)
handler.run (3000)
