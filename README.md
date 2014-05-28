===========
Python-SJCL
===========

Decrypt and encrypt messages compatible to the "Stanford Javascript Crypto
Library (SJCL)" message format.

This module was created while programming and testing the encrypted
blog platform on cryptedblog.com which is based on sjcl.

Typical usage often looks like this:

    #!/usr/bin/env python

    from sjcl import SJCL

    cyphertext = SJCL().encrypt("secret message to encrypt", "shared_secret")

    print cyphertext
    print SJCL().decrypt(cyphertext, "shared_secret")

