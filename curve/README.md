Elliptic curve x25519 and x448 in V-language
--------------------------------------------

This module provides two function specified in RFC 7748 Elliptic Curves for Security, 
in the form of x25519 and x448 functions for elliptic curves over prime fields.
For arithmatic operations, this module relies on `v_gmp` module from VincentLaisney, 
availables at https://github.com/VincentLaisney/v_gmp. It was V-lang binding  
to `GMP`, The GNU Multiple Precision Arithmetic Library, that mostly available 
on all platform.

WARNING 
=======

This module was work in progress, toys stuff just for learning cryptography and maybe not suite
for production, not fully tested (even the test getting passed, see the test). 
Use this with your own risk and you've been warned!


@2021 blackshirt
----------------