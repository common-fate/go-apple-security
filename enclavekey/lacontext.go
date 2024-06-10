package enclavekey

// LAContext is a mechanism for evaluating authentication policies and access controls.
//
// See: https://developer.apple.com/documentation/localauthentication/lacontext
type LAContext struct {
	// LocalizedReason is the localized explanation for
	// authentication shown in the dialog presented to the user.
	LocalizedReason string
}
