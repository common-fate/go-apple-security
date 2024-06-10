package enclavekey

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework Foundation -framework LocalAuthentication

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Foundation/Foundation.h>
#include <LocalAuthentication/LocalAuthentication.h>

typedef struct {
	char *LocalizedReason;
} LAContextOptions;

static LAContext* CreateLAContext(LAContextOptions options) {
	LAContext *context = [[LAContext alloc] init];
	context.localizedReason = [NSString stringWithUTF8String: options.LocalizedReason];
	return context;
}
*/
import "C"

import (
	"crypto"
	"errors"
	"io"
	"unsafe"

	"github.com/common-fate/go-apple-security/corefoundation"
)

func (k *Key) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("digest was empty")
	}

	appLabel, err := corefoundation.NewCFData(k.ApplicationLabel)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(appLabel))

	m := corefoundation.PointerDictionary{
		corefoundation.TypeRef(C.kSecClass):                unsafe.Pointer(C.CFTypeRef(C.kSecClassKey)),
		corefoundation.TypeRef(C.kSecAttrKeyType):          unsafe.Pointer(C.CFTypeRef(C.kSecAttrKeyTypeEC)),
		corefoundation.TypeRef(C.kSecAttrApplicationLabel): unsafe.Pointer(C.CFTypeRef(appLabel)),
		corefoundation.TypeRef(C.kSecAttrKeyClass):         unsafe.Pointer(C.CFTypeRef(C.kSecAttrKeyClassPrivate)),
		corefoundation.TypeRef(C.kSecReturnRef):            unsafe.Pointer(C.CFTypeRef(C.kCFBooleanTrue)),
		corefoundation.TypeRef(C.kSecMatchLimit):           unsafe.Pointer(C.CFTypeRef(C.kSecMatchLimitOne)),
	}

	if k.LAContext != nil {
		reason := C.CString(k.LAContext.LocalizedReason)
		defer C.free(unsafe.Pointer(reason))

		laContext := C.CreateLAContext(C.LAContextOptions{LocalizedReason: reason})
		defer C.free(unsafe.Pointer(laContext))

		m[corefoundation.TypeRef(C.kSecUseAuthenticationContext)] = unsafe.Pointer(laContext)
	}

	query, err := corefoundation.NewPointerDictionary(m)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var key C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &key)
	if err := goError(status); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(key))

	cfDigest, err := corefoundation.NewCFData(digest)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	var eref C.CFErrorRef
	signature := C.SecKeyCreateSignature(C.SecKeyRef(key), C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, C.CFDataRef(cfDigest), &eref)
	if err := goError(eref); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(signature))

	return C.GoBytes(
		unsafe.Pointer(C.CFDataGetBytePtr(signature)),
		C.int(C.CFDataGetLength(signature)),
	), nil
}
