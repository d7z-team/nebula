## `cert`

This package parses, verifies, creates, and signs Nebula certificates and authorities.

Use `CreateCA` and `IssueCertificate` for in-process certificate issuance. Key-only
workflows can use `GenerateSigningKey` and `GenerateKeyAgreementKey`. PEM, CA pool,
and encrypted signing-key APIs remain available.

There are now 2 versions of `nebula` certificates:

## v1

This version is deprecated.

A `protobuf` definition of the certificate format is included at `cert_v1.proto`

To compile the definition you will need `protoc` installed.

To compile for `go` with the same version of protobuf specified in go.mod:

```bash
make -C cert proto
```

## v2

This is the latest version which uses asn.1 DER encoding. It can support ipv4 and ipv6 and tolerate
future certificate changes better than v1.

`cert_v2.asn1` defines the wire format and can be used to compile marshalers.
