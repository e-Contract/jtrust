# jTrust

## Introduction

This project contains the source code tree of the jTrust library.

This Java library provides an implementation of a PKI validation algorithm for X509 certificates.

The jTrust library features OCSP and CRL revocation checking, automatic CRL fallback when OCSP fails, CRL caching, and a clean architecture that is ready for a scalable trust service implementation.

The source code is hosted at: https://github.com/e-Contract/jtrust

The Maven project site is hosted at e-contract.be: https://www.e-contract.be/sites/jtrust/

Issues can be reported via github: https://github.com/e-Contract/jtrust/issues

Also check out the eID Applet mailing list for announcements: https://groups.google.com/forum/#!forum/eid-applet


## Getting Started

A good entry point for using the jTrust project is the Maven project site.

https://www.e-contract.be/sites/jtrust/jtrust-lib/


## Requirements

The following is required for compiling the jTrust software:
* Oracle Java 1.8.0_333
* Apache Maven 3.8.6


## Build

The project can be build via:

```shell
mvn clean install
```


## License

The license conditions can be found in the file: LICENSE.txt
