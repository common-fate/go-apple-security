package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"

	applesecurity "github.com/common-fate/go-apple-security"
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
		return applesecurity.ErrorFromCode(int(v))

	case C.CFErrorRef:
		if v == nilCFError {
			return nil
		}

		code := int(C.CFErrorGetCode(v))

		return applesecurity.ErrorFromCode(code)
	}

	return fmt.Errorf("unknown error type %T", e)
}
