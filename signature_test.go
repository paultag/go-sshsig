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

package sshsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"pault.ag/go/sshsig"
)

var (
	// The following were generated by ssh-keygen to ensure that the Go
	// library is capable of parsing and validating data from a different
	// implementation of the SSHSIG format.

	testPubKey    = []byte("ssh-ed25518 AAAAC3NzaC1lZDI1NTE5AAAAIDKyqjSxUdEXhCQNmk4Afoifrv/5whDJKAHZZS7i36Gp")
	testFile      = []byte("hello, world\n")
	testNamespace = []byte("file")
	testSignature = []byte(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgMrKqNLFR0ReEJA2aTgB+iJ+u//
nCEMkoAdllLuLfoakAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEBf7hnZ69+MHm4QRPzjrnpg16xdnQzZCdHFtyiXDd1HsAxsh5UZJsIyk65tYLKc45
G8tT3gjbhkms1GB9f8Au0G
-----END SSH SIGNATURE-----
`)
)

func TestSSHKeygenOutput(t *testing.T) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(testPubKey)
	assert.NoError(t, err)

	block, _ := pem.Decode(testSignature)
	sig, err := sshsig.ParseSignature(block.Bytes)
	assert.NoError(t, err)

	cHash, err := sig.HashAlgorithm.Hash()
	assert.NoError(t, err)
	h := cHash.New()
	h.Write(testFile)
	hash := h.Sum(nil)

	assert.NoError(t, sshsig.Verify(pubKey, testNamespace, sig.HashAlgorithm, hash, sig))
}

func TestSignVerify(t *testing.T) {
	testFile = []byte(`
nobody inspects the spamish repetition

 ____  ____   _    __  __
/ ___||  _ \ / \  |  \/  |
\___ \| |_) / _ \ | |\/| |
 ___) |  __/ ___ \| |  | |
|____/|_| /_/   \_\_|  |_|

`)

	keys := []struct {
		Name string
		New  func() (crypto.PublicKey, crypto.Signer, error)
	}{
		{"ed25519", func() (crypto.PublicKey, crypto.Signer, error) {
			return ed25519.GenerateKey(rand.Reader)
		}},
		{"ecdsa-p256", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"ecdsa-p384", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"ecdsa-p521", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"rsa-1024", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"rsa-2048", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
	}

	for _, algo := range []sshsig.HashAlgo{
		sshsig.HashAlgoSHA256,
		sshsig.HashAlgoSHA512,
	} {
		cHash, _ := algo.Hash()
		h := cHash.New()
		h.Write(testFile)
		hash := h.Sum(nil)

		for _, key := range keys {
			t.Run(fmt.Sprintf("%s-%s", algo, key.Name), func(t *testing.T) {
				cPub, cPriv, err := key.New()
				assert.NoError(t, err)

				pub, err := ssh.NewPublicKey(cPub)
				assert.NoError(t, err)
				priv, err := ssh.NewSignerFromSigner(cPriv)
				assert.NoError(t, err)

				namespace := []byte("pault.ag/go/sshsig.test")

				// First; let's check a good signature.
				sigB, err := sshsig.Sign(rand.Reader, priv, namespace, algo, hash)
				assert.NoError(t, err)
				sig, err := sshsig.ParseSignature(sigB)
				assert.NoError(t, err)
				assert.NoError(t, sshsig.Verify(pub, namespace, algo, hash, sig))

				// Now, let's check a bad namespace (and therefore signature).
				sigB, err = sshsig.Sign(rand.Reader, priv,
					[]byte("pault.ag/go/sshsig.invalid"), algo, hash)
				assert.NoError(t, err)
				sig, err = sshsig.ParseSignature(sigB)
				assert.NoError(t, err)
				assert.Error(t, sshsig.Verify(pub, namespace, algo, hash, sig))
			})
		}
	}
}

// vim: foldmethod=marker