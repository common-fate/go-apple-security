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

const (
	nilCFData C.CFDataRef = 0
)

type GetGenericPasswordInput struct {
	Account string
	Service string
}

func GetGenericPassword(input GetGenericPasswordInput) (*GenericPassword, error) {
	cfAccount, err := corefoundation.NewCFString(input.Account)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	cfService, err := corefoundation.NewCFString(input.Service)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	query, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecAttrAccount):               corefoundation.TypeRef(cfAccount),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
		corefoundation.TypeRef(C.kSecReturnAttributes):          corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecReturnData):                corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecMatchLimit):                corefoundation.TypeRef(C.kSecMatchLimitOne),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var itemRef C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &itemRef)
	if err := goError(status); err != nil {
		return nil, err
	}
	defer C.CFRelease(itemRef)

	return extractGenericPassword(C.CFDictionaryRef(itemRef))
}
