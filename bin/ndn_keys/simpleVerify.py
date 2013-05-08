#!/usr/bin/env python

import sys, os

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"
    exit(1)

NDN_rootKeySha256 = "\xA7\xD9\x8B\x81\xDE\x13\xFCV\xC5\xA6\x92\xB4D\x93nVp\x9DRop\xED9\xEF\xB5\xE2\x03\x29\xA5S\x3Eh"
NDN_root = str(pyccn.Name ("/ndn/keys/").append ("\xC1.M.K\x00" + NDN_rootKeySha256).append ("\xFD\x01\x00P\x81\xBB\x3D").append("\x00"))

from verify import key_verifier
from M2Crypto import X509
import binascii
from xml.etree import ElementTree

class SimpleVerify(key_verifier):

    def getKeyName(self):
        if not self.args.keyprefix:
            sys.stderr.write('Error: key prefix is not specified\n')
            sys.exit(1)

        if self.args.keyfile:
            if os.path.isfile(self.args.keyfile):
                keyDer = X509.load_cert(self.args.keyfile, X509.FORMAT_PEM).get_pubkey().as_der()
                return [pyccn.Name(self.args.keyprefix).appendKeyID(pyccn.Key().fromDER(public=keyDer))]
            else:
                sys.stderr.write('Error: Key file does not exist\n')
                sys.exit(1)
        elif self.args.keyhash:
            return [pyccn.Name(self.args.keyprefix).append(b'\xc1.M.K\x00'+binascii.a2b_hex(self.args.keyhash))]
        elif self.args.keycert:
            sys.stderr.write('Error: Key cert not implemented\n')
            sys.exit(1)
        else:
            keyname = pyccn.Name(self.args.keyprefix)
            if len(keyname[-1]) > 6 and b'\xc1.M.K\x00' == keyname[len(keyname)-1][:6]:
                return [keyname]
            else:
                return self.searchKey(pyccn.Name(self.args.keyprefix))

    def searchKey(self, name):
        keys = []

        base_len = len (name)
        excludeList = []
        while True:
            interestName = pyccn.Name (name)
            exclude1 = pyccn.ExclusionFilter ()
            exclude1.add_names ([pyccn.Name().append (n) for n in excludeList])
            interest_tmpl = pyccn.Interest (exclude = exclude1, interestLifetime=self.args.timeout, minSuffixComponents=1, maxSuffixComponents=100, scope=self.args.scope)

            class Slurp(pyccn.Closure):
                def __init__(self):
                    self.finished = False
                    self.done = False

                def upcall(self, kind, upcallInfo):
                    if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
                        co = upcallInfo.ContentObject
                        self.name = co.name
                        # print co.name
                        if len (co.name) == base_len:
                            self.done = True
                        else:
                            excludeList.append (co.name[base_len])
                    elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
                        self.done = True

                    self.finished = True
                    return pyccn.RESULT_OK

            slurp = Slurp ()
            self.ccn.expressInterest(interestName, slurp, interest_tmpl)
            while not slurp.finished:
                # print slurp.finished
                self.ccn.run (1)

            if slurp.done:
                # print "Done with %s" % interestName
                break

            if slurp.name [base_len][0:5] == '\xc1.M.K':
                if slurp.name [base_len-1] != "info":
                    # if it is not a real key, but just meta
                    keyname = slurp.name[0:base_len+1]
                    keys.append (pyccn.Name (keyname))

        return keys

    def getCorrectVersion(self):
        if self.args.keycert:
            if os.path.isfile(self.args.keycert):
                keyName = pyccn.Name()

                nameNode = ElementTree.parse(self.args.keycert).getroot().find('Name')
                for child in nameNode:
                    if child.attrib['ccnbencoding'] == 'text':
                        keyName = keyName.append(child.text)
                    elif child.attrib['ccnbencoding'] == 'hexBinary':
                        keyName = keyName.append(binascii.a2b_hex(child.text))
                print keyName[:-1]
            else:
                sys.stderr.write('Error:Key cert does not exist!\n')
                sys.exit(1)
        else:
            keys = self.getKeyName()
            for keyname in sorted ([str(key) for key in keys]):
                verified = self.getVerifiedKey(pyccn.Name(keyname), "    ")
            
                if verified:
                    if self.args.verbose:
                        print ""
                    print pyccn.Name(verified.name[:-1])

