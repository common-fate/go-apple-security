package enclavekey

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound = errors.New("the specified item could not be found in the keychain")
)

const (
	nilCFError  C.CFErrorRef  = 0
	nilCFString C.CFStringRef = 0
)


func goError(e interface{}) error {
	if e == nil {
		return nil
	}

	switch v := e.(type) {
	case C.OSStatus:
		switch v {
		case 0:
			return nil
		case -25300:
			return ErrNotFound
		}
		return osStatusError{code: int(v)}

	case C.CFErrorRef:
		if v == nilCFError {
			return nil
		}

		code := int(C.CFErrorGetCode(v))
		if desc := C.CFErrorCopyDescription(v); desc != nilCFString {
			defer C.CFRelease(C.CFTypeRef(desc))

			if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
				str := C.GoString(cstr)

				return fmt.Errorf("CFError %d (%s)", code, str)
			}

		}
		return fmt.Errorf("CFError %d", code)
	}

	return fmt.Errorf("unknown error type %T", e)
}

type osStatusError struct {
	code int
}

func (oserr osStatusError) Error() string {
	return fmt.Sprintf("OSStatus %d", oserr.code)
}
