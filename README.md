# Golang Cryptographic Study

This study is based on [Golang Cryptography for Depeloper](https://leanpub.com/cryptog) book and its examples.

* [Symetric](cmd/symetric/main.go)  example with **confidentiality** and **authenticity(MAC)** algorithm. \
The cipher XSalsa20 is checked against a mac called Poly1305 to assure the authenticity of the source.