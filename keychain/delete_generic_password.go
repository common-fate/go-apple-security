package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"github.com/common-fate/go-apple-security/corefoundation"
)

type DeleteGenericPasswordsInput struct {
	Account string
	Service string
}

// DeleteGenericPasswords deletes matching items from the keychain.
func DeleteGenericPasswords(input DeleteGenericPasswordsInput) (int, error) {
	cfService, err := corefoundation.NewCFString(input.Service)
	if err != nil {
		return 0, err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	m := corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
	}

	if input.Account != "" {
		cfAccount, err := corefoundation.NewCFString(input.Account)
		if err != nil {
			return 0, err
		}
		defer C.CFRelease(C.CFTypeRef(cfAccount))

		m[corefoundation.TypeRef(C.kSecAttrAccount)] = corefoundation.TypeRef(cfAccount)
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
