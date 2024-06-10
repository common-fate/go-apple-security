package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// GenericPassword is a generic password item.
//
// See: https://developer.apple.com/documentation/security/ksecclassgenericpassword
type GenericPassword struct {
	Account string
	Service string
	Data    []byte
}
