package keychain

import (
	"errors"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestGenericPassword_AddRemove(t *testing.T) {
	tests := []struct {
		name    string
		input   GenericPassword
		wantErr bool
	}{
		{
			name: "ok",
			input: GenericPassword{
				Account: "foo",
				Service: "bar",
				Data:    []byte("hello"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// remove any existing keychain item,
			// otherwise Add will always fail.
			_, err := DeleteGenericPasswords(DeleteGenericPasswordsInput{
				Account: tt.input.Account,
				Service: tt.input.Service,
			})
			if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
				t.Fatal(err)
			}

			if err := AddGenericPassword(tt.input); (err != nil) != tt.wantErr {
				t.Errorf("GenericPassword.Add() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
