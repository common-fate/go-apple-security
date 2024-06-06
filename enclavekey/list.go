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

type ListInput struct {
	Tag   string
	Label string
}

// List keys matching the criteria specified in ListInput.
//
// Returns applesecurity.ErrNotFound if no keys are found.
func List(input ListInput) ([]Key, error) {
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
		corefoundation.TypeRef(C.kSecReturnAttributes):   corefoundation.TypeRef(C.kCFBooleanTrue),
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

	var resultsRef C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &resultsRef)
	if err := goError(status); err != nil {
		return nil, err
	}

	var results []Key

	typeID := C.CFGetTypeID(resultsRef)
	if typeID == C.CFArrayGetTypeID() {
		arr := corefoundation.CFArrayToArray(corefoundation.ArrayRef(resultsRef))
		for _, ref := range arr {
			elementTypeID := C.CFGetTypeID(C.CFTypeRef(ref))
			if elementTypeID != C.CFDictionaryGetTypeID() {
				return nil, fmt.Errorf("Invalid result type within array: %s", CFTypeDescription(C.CFTypeRef(ref)))
			}

			key, err := convertResult(C.CFDictionaryRef(ref))
			if err != nil {
				return nil, err
			}
			results = append(results, key)
		}
	} else {
		return nil, fmt.Errorf("Invalid result type: %s", CFTypeDescription(resultsRef))
	}

	return results, nil
}

func convertResult(d C.CFDictionaryRef) (Key, error) {
	keyRef := C.SecKeyRef(C.CFDictionaryGetValue(d, unsafe.Pointer(C.CFStringRef(C.kSecValueRef))))
	pubkey, err := extractPubKey(keyRef)
	if err != nil {
		return Key{}, err
	}

	var result Key
	result.Label = corefoundation.GetDictionaryStringValue(corefoundation.DictionaryRef(d), corefoundation.StringRef(C.kSecAttrLabel))
	result.Tag = string(corefoundation.GetDictionaryDataValue(corefoundation.DictionaryRef(d), corefoundation.DataRef(C.kSecAttrApplicationTag)))
	result.ApplicationLabel = corefoundation.GetDictionaryDataValue(corefoundation.DictionaryRef(d), corefoundation.DataRef(C.kSecAttrApplicationLabel))

	result.PublicKey = rawToEcdsa(pubkey.Key)

	return result, nil
}

// CFTypeDescription returns type string for CFTypeRef.
func CFTypeDescription(ref C.CFTypeRef) string {
	typeID := C.CFGetTypeID(ref)
	typeDesc := C.CFCopyTypeIDDescription(typeID)
	defer C.CFRelease(C.CFTypeRef(typeDesc))
	return corefoundation.CFStringToString(corefoundation.StringRef(typeDesc))
}
