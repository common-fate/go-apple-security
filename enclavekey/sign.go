package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"crypto"
	"errors"
	"io"
	"unsafe"

	"github.com/common-fate/go-apple-security/corefoundation"
)

func (k *Key) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("digest was empty")
	}

	appLabel, err := corefoundation.NewCFData(k.ApplicationLabel)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(appLabel))

	m := corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                corefoundation.TypeRef(C.kSecClassKey),
		corefoundation.TypeRef(C.kSecAttrKeyType):          corefoundation.TypeRef(C.kSecAttrKeyTypeEC),
		corefoundation.TypeRef(C.kSecAttrApplicationLabel): corefoundation.TypeRef(appLabel),
		corefoundation.TypeRef(C.kSecAttrKeyClass):         corefoundation.TypeRef(C.kSecAttrKeyClassPrivate),
		corefoundation.TypeRef(C.kSecReturnRef):            corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecMatchLimit):           corefoundation.TypeRef(C.kSecMatchLimitOne),
	}

	query, err := corefoundation.NewCFDictionary(m)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var key C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &key)
	if err := goError(status); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(key))

	cfDigest, err := corefoundation.NewCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	var eref C.CFErrorRef
	signature := C.SecKeyCreateSignature(C.SecKeyRef(key), C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, C.CFDataRef(cfDigest), &eref)
	if err := goError(eref); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(signature))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(signature)),
		C.int(C.CFDataGetLength(signature)),
	), nil
}
