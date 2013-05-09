#!/usr/bin/env python

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"
    exit(1)

import sys, os, time
import binascii
from M2Crypto import X509
from xml.etree import ElementTree

class KeyPublisher():
    def __init__(self, args):
        self.args = args

    def _setKeyBits(self):
        if not self.args.keyfile:
            sys.stderr.write('Error: key file not specified\n')
            sys.exit(1)
        elif not os.path.isfile(self.args.keyfile):
            sys.stderr.write('Error: key file does not exist\n')
            sys.exit(1)
        
        self.keybits = X509.load_cert(self.args.keyfile, X509.FORMAT_PEM).get_pubkey().as_der()

    def _setMeta(self):
        if not self.args.identity or not self.args.affiliation or not self.args.validity:
            sys.stderr.write('Error: identity or affiliation or validity not specified\n')
            sys.exit(1)
        
        validTo = int(time.time() + 0.5 + self.args.validity*24*3600)

        self.meta = '<Meta><Name>' + self.args.identity + '</Name><Affiliation>' + self.args.affiliation + '</Affiliation><Valid_to>' + str(validTo) + '</Valid_to></Meta>'

    def _setKeyName(self):
        if not self.args.keyprefix:
            sys.stderr.write('Error: pub key prefix not specified\n')
            sys.exit(1)

        pubKey = pyccn.Key()
        pubKey.fromDER(public=self.keybits)

        if not self.args.version:
            version = 'fd01'+"%0.10x" % int(time.time() + 0.5)
        else:
            version = self.args.version

        self.keyName = pyccn.Name(self.args.keyprefix).appendKeyID(pubKey).append(binascii.a2b_hex(version))

    def _setSignKeyReady(self):
        if not self.args.signkeyprefix and not self.args.signkeycert:
            sys.stderr.write('Error: signing key name and cert not specified\n')
            sys.exit(1)

        if not self.args.keystorepath:
            sys.stderr.write('Error: signing keystore not specified\n')
            sys.exit(1)
            
        if self.args.signkeyprefix:
            self.signkeyName = pyccn.Name(self.args.signkeyprefix)
        elif self.args.signkeycert:
            if not os.path.isfile(self.args.signkeycert):
                sys.stderr.write('Error: signing key cert does not exist\n')
                sys.exit(1)
            else:
                keyName = pycnn.Name()
                nameNode = ElementTree.parse(self.args.signkeycert).getroot().find('Name')
                for child in nameNode:
                    if child.attrib['ccnbencoding'] == 'text':
                        keyName = keyName.append(child.text)
                    elif child.attrib['ccnbencoding'] == 'hexBinary':
                        keyName = keyName.append(binascii.a2b_hex(child.text))
                self.signkeyName = keyName

        os.environ['HOME'] = self.args.keystorepath

    def _setCertFile(self):
        if self.args.cert:
            self.certFile = self.args.cert
        else:
            self.certFile = os.path.splitext(self.args.keyfile)[0] + '.pcert'

    def init(self):
        self._setKeyBits()
        self._setMeta()
        self._setKeyName()
        self._setCertFile()
        self._setSignKeyReady()

    def publish(self):
        print 'publish'

    def show(self):
        print 'KeyBits ' + binascii.b2a_hex(self.keybits)
        print 'KeyMeta ' + self.meta
        print 'KeyName ' + str(self.keyName)
        print 'CertFile ' + self.certFile
        print 'SignKey ' + str(self.signkeyName)
        print 'KeyStore ' + self.args.keystorepath
