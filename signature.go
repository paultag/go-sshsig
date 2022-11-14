// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com> 2022
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package sshsig

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// HashAlgo represents the hash function used to sign the data.
type HashAlgo string

// Hash will return the crypto.Hash object that relates to the specified
// hashing algorithm.
func (ha HashAlgo) Hash() (crypto.Hash, error) {
	switch ha {
	case HashAlgoSHA256:
		return crypto.SHA256, nil
	case HashAlgoSHA512:
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), ErrUnknownHashAlgorithm
	}
}

// Check will ensure that the Hash Algorithm is understood by sshsig.
func (ha HashAlgo) Check() error {
	switch ha {
	case HashAlgoSHA256:
		return nil
	case HashAlgoSHA512:
		return nil
	default:
		return ErrUnknownHashAlgorithm
	}
}

var (
	// ErrUnknownHashAlgorithm will be returned if the HashAlgo is not
	// understood by this implementation.
	ErrUnknownHashAlgorithm = fmt.Errorf("sshsig: Unknown Hash Algorithm")

	// ErrBadMagic will be returned if the Magic preamble is not correct
	// for an SSHSIG packet.
	ErrBadMagic = fmt.Errorf("sshsig: Bad Magic Preamble")

	// ErrUnknownVersion will be returned if the Version is different than
	// the library supported (currently, only version 1 is supported).
	ErrUnknownVersion = fmt.Errorf("sshsig: Unknown Version")

	// HashAlgoSHA512 is the SHA512 algorithm.
	HashAlgoSHA512 HashAlgo = "sha512"

	// HashAlgoSHA256 is the SHA256 algorithm.
	HashAlgoSHA256 HashAlgo = "sha256"

	// MagicPreamble is the first 6 bytes of any Signature.
	MagicPreamble = [6]byte{'S', 'S', 'H', 'S', 'I', 'G'}
)

// signature is the line-format version of the OpenSSH signature. This isn't
// exported to users, since we need to do a bit of work to parse the underlying
// data, and the data at this level isn't a very friendly way to interact with
// the signature.
//
// After parsing and validation, this will be moved and exported into the
// Signature type.
type signature struct {
	Magic         [6]byte
	Version       uint32
	PublicKey     []byte
	Namespace     []byte
	Reserved      []byte
	HashAlgorithm string
	Signature     []byte
}

// Check will ensure that the Signature is well-formed.
func (sig signature) Check() error {
	if bytes.Compare(sig.Magic[:], MagicPreamble[:]) != 0 {
		return ErrBadMagic
	}
	if sig.Version != 1 {
		return ErrUnknownVersion
	}
	if err := HashAlgo(sig.HashAlgorithm).Check(); err != nil {
		return err
	}
	return nil
}

// Signature contains the fields of an OpenSSH SSHSIG Signature, as read
// from the underlying wire data. All of the fields of this struct are
// user-provided and not safe to consider trusted without other verification.
type Signature struct {
	// Version is the major version of the SSHSIG protocol. Currently, only
	// Version 1 is supported; any other version is not understood
	// and will result in an error.
	Version uint32

	// PublicKey is the underlying SSH Public Key used to create the signature.
	// This is user provided, and not to be treated as validated or otherwise
	// trustworthy until otherwise verified.
	PublicKey ssh.PublicKey

	// Namespace is a unique signature domain used to avoid copy-and-pasting
	// signatures between uses. Ensure your key signing scheme has a unique
	// namespace.
	Namespace []byte

	// HashAlgorithm is the algorithm used to sign the data.
	HashAlgorithm HashAlgo

	// Signature is an ssh Signature over the hash of the data.
	Signature *ssh.Signature
}

// Marshal will encode the Signature into the SSHSIG Wire format.
func (sig Signature) Marshal() []byte {
	return ssh.Marshal(signature{
		Magic:         MagicPreamble,
		Version:       sig.Version,
		PublicKey:     sig.PublicKey.Marshal(),
		Namespace:     sig.Namespace,
		Reserved:      nil,
		HashAlgorithm: string(sig.HashAlgorithm),
		Signature:     ssh.Marshal(sig.Signature),
	})
}

// ParseSignature will unpack the wire-protocol version of an SSHSIG format
// Signature into a Signature struct.
func ParseSignature(b []byte) (*Signature, error) {
	sig := &signature{}
	if err := ssh.Unmarshal(b, sig); err != nil {
		return nil, err
	}
	if err := sig.Check(); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(sig.PublicKey)
	if err != nil {
		return nil, err
	}

	sign := &ssh.Signature{}
	if err := ssh.Unmarshal(sig.Signature, sign); err != nil {
		return nil, err
	}

	return &Signature{
		Version:       sig.Version,
		PublicKey:     pubKey,
		Namespace:     sig.Namespace,
		HashAlgorithm: HashAlgo(sig.HashAlgorithm),
		Signature:     sign,
	}, nil
}

// signedData is the SSH line format used to create the data that is
// signed by the OpenSSH key. This isn't exported since I don't think this
// is a sensible user-facing API component.
type signedData struct {
	Namespace     []byte
	HashAlgorithm string
	Hash          []byte
}

// Marshal will serialize the hash and associated metadata into a "Signed Data"
// struct, for signing or verification.
func (sd signedData) Marshal() []byte {
	return ssh.Marshal(struct {
		Magic         [6]byte
		Namespace     []byte
		Reserved      []byte
		HashAlgorithm string
		Hash          []byte
	}{
		MagicPreamble,
		sd.Namespace,
		nil,
		sd.HashAlgorithm,
		sd.Hash,
	})
}

// Verify will check that the OpenSSH SSHSIG Signature is valid given the
// data hash, hash algorith, and namespace.
//
// This function expects that the HashAlgo is passed explicitly -- even though
// the Signature type also includes the HashAlgo, just for explicit
// re-confirmation that the passed Hash is of that type.
//
// This will only verify an SSHSIG v1 signature.
func Verify(
	pub ssh.PublicKey,
	namespace []byte,
	hashAlgo HashAlgo,
	hash []byte,
	sig *Signature,
) error {
	message := signedData{
		Namespace:     namespace,
		HashAlgorithm: string(hashAlgo),
		Hash:          hash,
	}.Marshal()
	return sig.PublicKey.Verify(message, sig.Signature)
}

// Sign will create an OpenSSH SSHSIG format Signature in the provdied namespace,
// with the provided Hash Algorith, and data hash. This will create an SSHSIG
// v1.
func Sign(
	rand io.Reader,
	priv ssh.Signer,
	namespace []byte,
	hashAlgo HashAlgo,
	hash []byte,
) ([]byte, error) {
	message := signedData{
		Namespace:     namespace,
		HashAlgorithm: string(hashAlgo),
		Hash:          hash,
	}.Marshal()
	sig, err := priv.Sign(rand, message)
	if err != nil {
		return nil, err
	}

	return Signature{
		Version:       1,
		PublicKey:     priv.PublicKey(),
		Namespace:     namespace,
		HashAlgorithm: hashAlgo,
		Signature:     sig,
	}.Marshal(), nil
}

// vim: foldmethod=marker
