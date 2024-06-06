package corefoundation

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	nilCFData   C.CFDataRef   = 0
	nilCFString C.CFStringRef = 0
)

type TypeRef = C.CFTypeRef

type Dictionary = map[TypeRef]TypeRef

func NewCFDictionary(m Dictionary) (C.CFDictionaryRef, error) {
	var (
		keys []unsafe.Pointer
		vals []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k))
		vals = append(vals, unsafe.Pointer(v))
	}

	ref := C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &vals[0], C.CFIndex(len(m)),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks)
	return ref, nil
}

func NewCFData(d []byte) (C.CFDataRef, error) {
	p := (*C.uchar)(C.CBytes(d))
	defer C.free(unsafe.Pointer(p))

	ref := C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(d)))
	if ref == nilCFData {
		return ref, fmt.Errorf("error creating CFData")
	}

	return ref, nil
}

func NewCFString(s string) (C.CFStringRef, error) {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))

	ref := C.CFStringCreateWithCString(C.kCFAllocatorDefault, p, C.kCFStringEncodingUTF8)
	if ref == nilCFString {
		return ref, fmt.Errorf("error creating CFString")
	}
	return ref, nil
}
