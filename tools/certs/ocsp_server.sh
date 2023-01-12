#!/bin/bash
openssl ocsp -index index.txt -port 8080 -rsigner rootCA.crt -rkey private/rootCA.key -CA rootCA.crt -text -out log.txt
