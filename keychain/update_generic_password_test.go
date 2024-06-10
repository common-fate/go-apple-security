package keychain

import (
	"errors"
	"reflect"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestUpdateGenericPassword(t *testing.T) {
	pw := GenericPassword{
		Account: "bar",
		Service: "foo",
		Data:    []byte("first"),
	}

	_, err := DeleteGenericPasswords(DeleteGenericPasswordsInput{
		Account: pw.Account,
		Service: pw.Service,
	})
	if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
		t.Fatal(err)
	}

	err = AddGenericPassword(pw)
	if err != nil {
		t.Fatal(err)
	}

	pw.Data = []byte("second")

	err = UpdateGenericPassword(pw)
	if err != nil {
		t.Fatal(err)
	}

	got, err := GetGenericPassword(GetGenericPasswordInput{
		Account: pw.Account,
		Service: pw.Service,
	})
	if err != nil {
		t.Errorf("GetGenericPassword() error = %v, wantErr %v", err, false)
		return
	}
	if !reflect.DeepEqual(got, &pw) {
		t.Errorf("GetGenericPassword() = %v, want %v", got, pw)
	}
}
