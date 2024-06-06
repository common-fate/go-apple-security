package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import "github.com/common-fate/go-apple-security/corefoundation"

// GenericPassword is a generic password item.
//
// See: https://developer.apple.com/documentation/security/ksecclassgenericpassword
type GenericPassword struct {
	Account string
	Service string
	Data    []byte
}

// Add the item to the keychain.
//
// Returns [ErrDuplicateItem] if the item already exists
// for the provided account and service.
func (p *GenericPassword) Add() error {
	valueData, err := corefoundation.NewCFData(p.Data)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(valueData))

	cfAccount, err := corefoundation.NewCFString(p.Account)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	cfService, err := corefoundation.NewCFString(p.Service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	attrs, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecValueData):                 corefoundation.TypeRef(valueData),
		corefoundation.TypeRef(C.kSecAttrAccount):               corefoundation.TypeRef(cfAccount),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	errCode := C.SecItemAdd(C.CFDictionaryRef(attrs), nil)

	return checkError(errCode)
}

// Remove the item from the keychain.
//
// Note: this does not return an error if the item doesn't exist.
func (p *GenericPassword) Remove() error {
	cfAccount, err := corefoundation.NewCFString(p.Account)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	cfService, err := corefoundation.NewCFString(p.Service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	attrs, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecAttrAccount):               corefoundation.TypeRef(cfAccount),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	errCode := C.SecItemDelete(C.CFDictionaryRef(attrs))

	return checkError(errCode)
}
