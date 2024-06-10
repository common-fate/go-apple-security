package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	applesecurity "github.com/common-fate/go-apple-security"
	"github.com/common-fate/go-apple-security/corefoundation"
)

// UpdateGenericPassword updates a generic password in the keychain.
func UpdateGenericPassword(input GenericPassword) error {
	valueData, err := corefoundation.NewCFData(input.Data)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(valueData))

	cfAccount, err := corefoundation.NewCFString(input.Account)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	cfService, err := corefoundation.NewCFString(input.Service)
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	query, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecValueData):                 corefoundation.TypeRef(valueData),
		corefoundation.TypeRef(C.kSecAttrAccount):               corefoundation.TypeRef(cfAccount),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	attrs, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecValueData):   corefoundation.TypeRef(valueData),
		corefoundation.TypeRef(C.kSecAttrAccount): corefoundation.TypeRef(cfAccount),
		corefoundation.TypeRef(C.kSecAttrService): corefoundation.TypeRef(cfService),
	})
	if err != nil {
		return err
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	errCode := C.SecItemUpdate(C.CFDictionaryRef(query), C.CFDictionaryRef(attrs))

	return applesecurity.ErrorFromCode(int(errCode))
}
