package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
)

const (
	nilSecKey           C.SecKeyRef           = 0
	nilCFData           C.CFDataRef           = 0
	nilCFDictionary     C.CFDictionaryRef     = 0
	nilCFType           C.CFTypeRef           = 0
	nilSecAccessControl C.SecAccessControlRef = 0
)

// Key is a NIST P-256 elliptic curve key
// backed by the secure enclave.
type Key struct {
	// ApplicationLabel is used to look up a key programmatically
	// and is the hash of a key
	ApplicationLabel []byte
	PublicKey        *ecdsa.PublicKey
	Tag              string
	Label            string
	// LAContext is the authentication context
	// to use when signing with this key.
	LAContext *LAContext
}

// rawToEcdsa turns an ASN.1 encoded byte stream to an ecdsa public key
// It is assumed that the curve of the key is P-256
func rawToEcdsa(raw []byte) *ecdsa.PublicKey {
	ecKey := new(ecdsa.PublicKey)
	ecKey.Curve = elliptic.P256()
	ecKey.X, ecKey.Y = elliptic.Unmarshal(ecKey.Curve, raw)
	return ecKey
}

// Public returns the public key of this key
func (k *Key) Public() crypto.PublicKey {
	return k.PublicKey
}
