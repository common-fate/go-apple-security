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
type ArrayRef = C.CFArrayRef
type StringRef = C.CFStringRef
type DataRef = C.CFDataRef
type DictionaryRef = C.CFDictionaryRef

type Dictionary = map[TypeRef]TypeRef
type PointerDictionary = map[TypeRef]unsafe.Pointer

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

func NewPointerDictionary(m PointerDictionary) (C.CFDictionaryRef, error) {
	var (
		keys []unsafe.Pointer
		vals []unsafe.Pointer
	)

	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k))
		vals = append(vals, v)
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

// CFArrayToArray converts a CFArrayRef to an array of CFTypes.
func CFArrayToArray(cfArray ArrayRef) (a []TypeRef) {
	count := C.CFArrayGetCount(cfArray)
	if count > 0 {
		a = make([]C.CFTypeRef, count)
		C.CFArrayGetValues(cfArray, C.CFRange{0, count}, (*unsafe.Pointer)(unsafe.Pointer(&a[0])))
	}
	return
}

// CFDictionaryToMap converts CFDictionaryRef to a map.
func CFDictionaryToMap(cfDict C.CFDictionaryRef) Dictionary {
	count := C.CFDictionaryGetCount(cfDict)
	if count > 0 {
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		C.CFDictionaryGetKeysAndValues(cfDict, (*unsafe.Pointer)(unsafe.Pointer(&keys[0])), (*unsafe.Pointer)(unsafe.Pointer(&values[0])))
		m := make(Dictionary, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}
		return m
	}
	return nil
}

func GetDictionaryDataValue(d DictionaryRef, ref DataRef) []byte {
	value := C.CFDataRef(C.CFDictionaryGetValue(d, unsafe.Pointer(ref)))
	if value == nilCFData {
		return nil
	}

	return CFDataToBytes(value)
}

func GetDictionaryStringValue(d DictionaryRef, ref StringRef) string {
	value := C.CFStringRef(C.CFDictionaryGetValue(d, unsafe.Pointer(ref)))
	if value == nilCFString {
		return ""
	}

	return CFStringToString(value)
}

// CFStringToString converts a CFStringRef to a string.
func CFStringToString(s StringRef) string {
	p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(s, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}

// CFDataToBytes converts CFData to bytes.
func CFDataToBytes(cfData C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cfData)), C.int(C.CFDataGetLength(cfData)))
}
