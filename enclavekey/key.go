package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
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
	Public *ecdsa.PublicKey
}

// rawToEcdsa turns an ASN.1 encoded byte stream to an ecdsa public key
// It is assumed that the curve of the key is P-256
func rawToEcdsa(raw []byte) *ecdsa.PublicKey {
	ecKey := new(ecdsa.PublicKey)
	ecKey.Curve = elliptic.P256()
	ecKey.X, ecKey.Y = elliptic.Unmarshal(ecKey.Curve, raw)
	return ecKey
}
