package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"github.com/common-fate/go-apple-security/corefoundation"
)

type ListInput struct {
	Tag   string
	Label string
}

// List keys matching the criteria specified in ListInput
func List(input ListInput) (*Key, error) {
	cfTag, err := corefoundation.NewCFData([]byte(input.Tag))
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	m := corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):              corefoundation.TypeRef(C.kSecClassKey),
		corefoundation.TypeRef(C.kSecAttrKeyType):        corefoundation.TypeRef(C.kSecAttrKeyTypeEC),
		corefoundation.TypeRef(C.kSecAttrApplicationTag): corefoundation.TypeRef(cfTag),
		corefoundation.TypeRef(C.kSecAttrKeyClass):       corefoundation.TypeRef(C.kSecAttrKeyClassPrivate),
		corefoundation.TypeRef(C.kSecReturnRef):          corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecMatchLimit):         corefoundation.TypeRef(C.kSecMatchLimitAll),
	}

	if input.Label != "" {
		cfLabel, err := corefoundation.NewCFString(input.Label)
		if err != nil {
			return nil, err
		}
		defer C.CFRelease(C.CFTypeRef(cfLabel))

		m[corefoundation.TypeRef(C.kSecAttrLabel)] = corefoundation.TypeRef(cfLabel)
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

	pubkey, err := extractPubKey(C.SecKeyRef(key))
	if err != nil {
		return nil, err
	}

	result := Key{
		Public: rawToEcdsa(pubkey),
	}

	return &result, nil
}
