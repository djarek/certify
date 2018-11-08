# Platform-specific TLS keystore abstraction for use with Boost.ASIO and OpenSSL

| Linux/OSX | Windows
|-----------|---------
[![Build Status](https://travis-ci.org/djarek/certify.svg?branch=master)](https://travis-ci.org/djarek/certify) | [![Build status](https://ci.appveyor.com/api/projects/status/4u2oe4l7am609bv0?svg=true)](https://ci.appveyor.com/project/djarek/certify)



## Introduction
Certify is a header-only library which abstracts away the details of
accessing a platform's TLS keystore and performing verification of a
TLS peer's certificate, according to [RFC2818](https://tools.ietf.org/html/rfc2818).
The library depends on OpenSSL and is designed to be easy to integrate with `boost::asio::ssl`.
