package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/common-fate/go-apple-security/corefoundation"
)

type NewInput struct {
	// UserPresence constrains access to the key with
	// either biometry or passcode.
	//
	// See: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/ksecaccesscontroluserpresence
	UserPresence bool

	// Tag data is constructed from a string, using reverse DNS notation, though any unique tag will do.
	//
	// For example: 'com.example.keys.mykey'.
	//
	// See: https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys#2863927
	Tag string

	Label string
}

// New creates a new ECDSA P-256 key backed by the Secure Enclave.
func New(input NewInput) (*Key, error) {
	protection := C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
	flags := C.kSecAccessControlPrivateKeyUsage

	if input.UserPresence {
		flags |= C.kSecAccessControlUserPresence
	}

	cfTag, err := corefoundation.NewCFData([]byte(input.Tag))
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	// cfLabel, err := newCFString(label)
	// if err != nil {
	// 	return nil, err
	// }
	// defer C.CFRelease(C.CFTypeRef(cfLabel))

	var eref C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(protection),
		C.SecAccessControlCreateFlags(flags),
		&eref)

	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(access))

	privKeyAttrs, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecAttrAccessControl):  corefoundation.TypeRef(access),
		corefoundation.TypeRef(C.kSecAttrApplicationTag): corefoundation.TypeRef(cfTag),
		corefoundation.TypeRef(C.kSecAttrIsPermanent):    corefoundation.TypeRef(C.kCFBooleanTrue),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(privKeyAttrs))

	m := corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecAttrTokenID):     corefoundation.TypeRef(C.kSecAttrTokenIDSecureEnclave),
		corefoundation.TypeRef(C.kSecAttrKeyType):     corefoundation.TypeRef(C.kSecAttrKeyTypeEC),
		corefoundation.TypeRef(C.kSecPrivateKeyAttrs): corefoundation.TypeRef(privKeyAttrs),
	}

	if input.Label != "" {
		cfLabel, err := corefoundation.NewCFString(input.Label)
		if err != nil {
			return nil, err
		}
		defer C.CFRelease(C.CFTypeRef(cfLabel))

		m[corefoundation.TypeRef(C.kSecAttrLabel)] = corefoundation.TypeRef(cfLabel)
	}

	attrs, err := corefoundation.NewCFDictionary(m)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	privKey := C.SecKeyCreateRandomKey(C.CFDictionaryRef(attrs), &eref)
	if err := goError(eref); err != nil {
		C.CFRelease(C.CFTypeRef(eref))
		return nil, err
	}
	if privKey == nilSecKey {
		return nil, fmt.Errorf("error generating random private key")
	}
	defer C.CFRelease(C.CFTypeRef(privKey))

	publicKey := C.SecKeyCopyPublicKey(privKey)
	if publicKey == nilSecKey {
		return nil, fmt.Errorf("error extracting public key")
	}
	defer C.CFRelease(C.CFTypeRef(publicKey))

	keyAttrs := C.SecKeyCopyAttributes(publicKey)
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	publicKeyData := C.CFDataRef(C.CFDictionaryGetValue(keyAttrs, unsafe.Pointer(C.kSecValueData)))

	keyBytes := C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(publicKeyData)),
		C.int(C.CFDataGetLength(publicKeyData)),
	)

	key := Key{
		Public: rawToEcdsa(keyBytes),
	}

	return &key, nil
}
