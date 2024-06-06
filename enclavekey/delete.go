package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import "github.com/common-fate/go-apple-security/corefoundation"

type DeleteInput struct {
	Tag   string
	Label string
}

// Delete keys in the keychain matching the criteria in DeleteInput.
//
// Multiple keys will be deleted if they all match the criteria.
//
// Returns a count of deleted keys. Returns ErrNotFound if no
// keys were found matching the criteria.
func Delete(input DeleteInput) (int, error) {
	cfTag, err := corefoundation.NewCFData([]byte(input.Tag))
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfTag))

	m := corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):              corefoundation.TypeRef(C.kSecClassKey),
		corefoundation.TypeRef(C.kSecAttrKeyType):        corefoundation.TypeRef(C.kSecAttrKeyTypeEC),
		corefoundation.TypeRef(C.kSecAttrApplicationTag): corefoundation.TypeRef(cfTag),
		corefoundation.TypeRef(C.kSecAttrKeyClass):       corefoundation.TypeRef(C.kSecAttrKeyClassPrivate),
	}

	if input.Label != "" {
		cfLabel, err := corefoundation.NewCFString(input.Label)
		if err != nil {
			return 0, err
		}
		defer C.CFRelease(C.CFTypeRef(cfLabel))

		m[corefoundation.TypeRef(C.kSecAttrLabel)] = corefoundation.TypeRef(cfLabel)
	}

	query, err := corefoundation.NewCFDictionary(m)
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var deleted int
	var st C.OSStatus = C.errSecDuplicateItem
	for st == C.errSecDuplicateItem {
		st = C.SecItemDelete(C.CFDictionaryRef(query))
		deleted++
	}
	if err := goError(st); err != nil {
		return deleted, err
	}
	return deleted, nil
}
