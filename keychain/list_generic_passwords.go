package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"

	applesecurity "github.com/common-fate/go-apple-security"
	"github.com/common-fate/go-apple-security/corefoundation"
)

type ListGenericPasswordsInput struct {
	Service string
}

func ListGenericPasswords(input ListGenericPasswordsInput) ([]GenericPassword, error) {
	cfService, err := corefoundation.NewCFString(input.Service)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfService))

	query, err := corefoundation.NewCFDictionary(corefoundation.Dictionary{
		corefoundation.TypeRef(C.kSecClass):                     corefoundation.TypeRef(C.kSecClassGenericPassword),
		corefoundation.TypeRef(C.kSecUseDataProtectionKeychain): corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecAttrService):               corefoundation.TypeRef(cfService),
		corefoundation.TypeRef(C.kSecReturnAttributes):          corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecReturnData):                corefoundation.TypeRef(C.kCFBooleanTrue),
		corefoundation.TypeRef(C.kSecMatchLimit):                corefoundation.TypeRef(C.kSecMatchLimitAll),
	})
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var resultsRef C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &resultsRef)
	err = goError(status)
	if errors.Is(err, applesecurity.ErrItemNotFound) {
		// no items found, return nil.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(resultsRef)

	var results []GenericPassword

	arr := corefoundation.CFArrayToArray(corefoundation.ArrayRef(resultsRef))
	for _, ref := range arr {
		elementTypeID := C.CFGetTypeID(C.CFTypeRef(ref))
		if elementTypeID != C.CFDictionaryGetTypeID() {
			return nil, fmt.Errorf("Invalid result type within array: %s", CFTypeDescription(C.CFTypeRef(ref)))
		}

		key, err := extractGenericPassword(C.CFDictionaryRef(ref))
		if err != nil {
			return nil, err
		}
		results = append(results, *key)
	}

	return results, nil
}

func extractGenericPassword(ref C.CFDictionaryRef) (*GenericPassword, error) {
	val := C.CFDataRef(C.CFDictionaryGetValue(ref, unsafe.Pointer(C.kSecValueData)))
	if val == nilCFData {
		return nil, fmt.Errorf("cannot extract data")
	}

	p := GenericPassword{
		Data: C.GoBytes(
			unsafe.Pointer(C.CFDataGetBytePtr(val)),
			C.int(C.CFDataGetLength(val)),
		),
		Account: corefoundation.GetDictionaryStringValue(corefoundation.DictionaryRef(ref), corefoundation.StringRef(C.kSecAttrAccount)),
		Service: corefoundation.GetDictionaryStringValue(corefoundation.DictionaryRef(ref), corefoundation.StringRef(C.kSecAttrService)),
	}

	return &p, nil
}

// CFTypeDescription returns type string for CFTypeRef.
func CFTypeDescription(ref C.CFTypeRef) string {
	typeID := C.CFGetTypeID(ref)
	typeDesc := C.CFCopyTypeIDDescription(typeID)
	defer C.CFRelease(C.CFTypeRef(typeDesc))
	return corefoundation.CFStringToString(corefoundation.StringRef(typeDesc))
}
