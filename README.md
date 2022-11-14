# pault.ag/go/sshsig - sign data using OpenSSH

[![GoDoc](https://godoc.org/pault.ag/go/sshsig?status.svg)](https://godoc.org/pault.ag/go/sshsig)

[![Go Report Card](https://goreportcard.com/badge/pault.ag/go/sshsig)](https://goreportcard.com/report/pault.ag/go/sshsig)

OpenSSH supports a new [SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
format, which allows for the signing of any data using an OpenSSH key.

This is supported on the CLI via `ssh-keygen -Y sign` (and associated `-Y` friends)
but, support for SSHSIG is not implemented in
[x/crypto](https://pkg.go.dev/golang.org/x/crypto/ssh).

I don't have the time to handle upstreaming this to `x/crypto`, but I'd very
much welcome someone upstreaming this (and deprecating this module), I'm happy
to sign whatever is needed to help with that, including relicensing for inclusion
into Go's `x/crypto`. Until then, this can do the work of signing and verification.
