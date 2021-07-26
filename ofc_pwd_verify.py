#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      sganachari
#
# Created:     23/07/2021
# Copyright:   (c) sganachari 2021
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import hashlib
from arc4 import ARC4

def main():
    salt = '\xaeK\xae\xc8\x92\xcc\x93\x82\xd5/\x86ll\xd0\xbe:'  #offset A8
    verifier = "\xCE\xBC\x0F\x24\xE7\x5A\x54\x92\xA2\xC4\xE8\xE4\xE3\x17\x9B\x30"  #offset b8
    ecrypted_verifier_hash = "\x11\xCE\xDA\xC8\x46\xBF\xD6\x46\x8C\xA3\x7A\x70\x5A\xDE\xAF\x14\x30\x35\x94\xB5" #Offset CC
    password = "VelvetSweatshop"

    #this example used  sha1 as hash algorith (0x00008004) and RC4 as Encryption algorithm (0x00006801) : these feilds are available in encryption header offset 0x2e and 0x32)
    pwd = password.encode('utf-16le')  #convert to wide and little endian
    hash1 = hashlib.sha1(salt+pwd).digest()
    hash2 = hashlib.sha1(hash1+'\x00\x00\x00\x00').digest()
    keylength = 0x80     #keylength is also defined in encryption header i., 0x00000080
    KEY = hash2[:keylength/8]

    #verification
    rc = ARC4(KEY)
    rc4_verifier = rc.decrypt(verifier)
    hash_rc4_verifier = hashlib.sha1(rc4_verifier).digest()
    rc4_encrytped_verifier_hash = rc.decrypt(ecrypted_verifier_hash)

    if (hash_rc4_verifier == rc4_encrytped_verifier_hash):
        print 'Password is Default Password '
    else:
        print 'Password is not default'


if __name__ == '__main__':
    main()
