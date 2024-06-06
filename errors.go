package applesecurity

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import "fmt"

// Error defines keychain errors
type Error int

var (
	// ErrUnimplemented corresponds to errSecUnimplemented result code
	ErrUnimplemented = Error(C.errSecUnimplemented)
	// ErrParam corresponds to errSecParam result code
	ErrParam = Error(C.errSecParam)
	// ErrAllocate corresponds to errSecAllocate result code
	ErrAllocate = Error(C.errSecAllocate)
	// ErrNotAvailable corresponds to errSecNotAvailable result code
	ErrNotAvailable = Error(C.errSecNotAvailable)
	// ErrAuthFailed corresponds to errSecAuthFailed result code
	ErrAuthFailed = Error(C.errSecAuthFailed)
	// ErrDuplicateItem corresponds to errSecDuplicateItem result code
	ErrDuplicateItem = Error(C.errSecDuplicateItem)
	// ErrItemNotFound corresponds to errSecItemNotFound result code
	ErrItemNotFound = Error(C.errSecItemNotFound)
	// ErrInteractionNotAllowed corresponds to errSecInteractionNotAllowed result code
	ErrInteractionNotAllowed = Error(C.errSecInteractionNotAllowed)
	// ErrDecode corresponds to errSecDecode result code
	ErrDecode = Error(C.errSecDecode)
	// ErrNoSuchKeychain corresponds to errSecNoSuchKeychain result code
	ErrNoSuchKeychain = Error(C.errSecNoSuchKeychain)
	// ErrNoAccessForItem corresponds to errSecNoAccessForItem result code
	ErrNoAccessForItem = Error(C.errSecNoAccessForItem)
	// ErrReadOnly corresponds to errSecReadOnly result code
	ErrReadOnly = Error(C.errSecReadOnly)
	// ErrInvalidKeychain corresponds to errSecInvalidKeychain result code
	ErrInvalidKeychain = Error(C.errSecInvalidKeychain)
	// ErrDuplicateKeyChain corresponds to errSecDuplicateKeychain result code
	ErrDuplicateKeyChain = Error(C.errSecDuplicateKeychain)
	// ErrWrongVersion corresponds to errSecWrongSecVersion result code
	ErrWrongVersion = Error(C.errSecWrongSecVersion)
	// ErrReadonlyAttribute corresponds to errSecReadOnlyAttr result code
	ErrReadonlyAttribute = Error(C.errSecReadOnlyAttr)
	// ErrInvalidSearchRef corresponds to errSecInvalidSearchRef result code
	ErrInvalidSearchRef = Error(C.errSecInvalidSearchRef)
	// ErrInvalidItemRef corresponds to errSecInvalidItemRef result code
	ErrInvalidItemRef = Error(C.errSecInvalidItemRef)
	// ErrDataNotAvailable corresponds to errSecDataNotAvailable result code
	ErrDataNotAvailable = Error(C.errSecDataNotAvailable)
	// ErrDataNotModifiable corresponds to errSecDataNotModifiable result code
	ErrDataNotModifiable = Error(C.errSecDataNotModifiable)
	// ErrInvalidOwnerEdit corresponds to errSecInvalidOwnerEdit result code
	ErrInvalidOwnerEdit = Error(C.errSecInvalidOwnerEdit)
	// ErrUserCanceled corresponds to errSecUserCanceled result code
	ErrUserCanceled = Error(C.errSecUserCanceled)
	// ErrMissingEntitlement corresponds to errSecMissingEntitlement result code
	ErrMissingEntitlement = Error(C.errSecMissingEntitlement)

	// ErrNotFound occurs when a keychain item is not found.
	ErrNotFound = Error(-25300)
)

type ErrorCode = C.OSStatus

func ErrorFromCode(errCode ErrorCode) error {
	if errCode == C.errSecSuccess {
		return nil
	}
	return Error(errCode)
}

func (k Error) Error() (msg string) {
	// SecCopyErrorMessageString is only available on OSX, so derive manually.
	// Messages derived from `$ security error $errcode`.
	switch k {
	case ErrUnimplemented:
		msg = "function or operation not implemented"
	case ErrParam:
		msg = "one or more parameters passed to the function were not valid"
	case ErrAllocate:
		msg = "failed to allocate memory"
	case ErrNotAvailable:
		msg = "no keychain is available. You may need to restart your computer"
	case ErrAuthFailed:
		msg = "the user name or passphrase you entered is not correct"
	case ErrDuplicateItem:
		msg = "the specified item already exists in the keychain"
	case ErrItemNotFound:
		msg = "the specified item could not be found in the keychain"
	case ErrInteractionNotAllowed:
		msg = "user interaction is not allowed"
	case ErrDecode:
		msg = "unable to decode the provided data"
	case ErrNoSuchKeychain:
		msg = "the specified keychain could not be found"
	case ErrNoAccessForItem:
		msg = "the specified item has no access control"
	case ErrReadOnly:
		msg = "read-only error"
	case ErrReadonlyAttribute:
		msg = "the attribute is read-only"
	case ErrInvalidKeychain:
		msg = "the keychain is not valid"
	case ErrDuplicateKeyChain:
		msg = "a keychain with the same name already exists"
	case ErrWrongVersion:
		msg = "the version is incorrect"
	case ErrInvalidItemRef:
		msg = "the item reference is invalid"
	case ErrInvalidSearchRef:
		msg = "the search reference is invalid"
	case ErrDataNotAvailable:
		msg = "the data is not available"
	case ErrDataNotModifiable:
		msg = "the data is not modifiable"
	case ErrInvalidOwnerEdit:
		msg = "an invalid attempt to change the owner of an item"
	case ErrUserCanceled:
		msg = "user canceled the operation"
	case ErrMissingEntitlement:
		msg = "a required entitlement is missing: ensure that your binary has been properly codesigned and has entitlements allowing keychain access"
	case ErrNotFound:
		msg = "the specified item could not be found in the keychain"
	default:
		msg = "keychain error"
	}
	return fmt.Sprintf("%s (%d)", msg, k)
}
