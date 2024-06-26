package enclavekey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestKey_Sign(t *testing.T) {
	type fields struct {
		Tag   string
		Label string
	}
	type args struct {
		digest []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Tag:   "com.example.goapplesecurity.test.key",
				Label: "example key",
			},
			args: args{
				digest: []byte("hello"),
			},
		},
		{
			name: "empty payload",
			fields: fields{
				Tag:   "com.example.goapplesecurity.test.key",
				Label: "example key",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// delete any existing keys
			_, err := Delete(DeleteInput{
				Tag:   tt.fields.Tag,
				Label: tt.fields.Label,
			})
			if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
				t.Fatalf("error deleting existing keys: %v", err)
			}

			// create a new key based on the provided input
			k, err := Create(CreateInput{
				Tag:   tt.fields.Tag,
				Label: tt.fields.Label,
			})
			if err != nil {
				t.Fatalf("error creating key: %v", err)
			}

			digest := sha256.Sum256([]byte(tt.args.digest))

			got, err := k.Sign(nil, digest[:], nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Key.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !ecdsa.VerifyASN1(k.PublicKey, digest[:], got) {
				t.Errorf("invalid signature")
			}
		})
	}
}

func TestKey_Sign_Interactive(t *testing.T) {
	if os.Getenv("INTERACTIVE") != "true" {
		t.Skipf("INTERACTIVE env var is not set")
	}

	tag := "com.example.goapplesecurity.test.key"
	label := "example key"
	digestInput := "hello"

	// delete any existing keys
	_, err := Delete(DeleteInput{
		Tag:   tag,
		Label: label,
	})
	if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
		t.Fatalf("error deleting existing keys: %v", err)
	}

	// create a new key based on the provided input
	k, err := Create(CreateInput{
		Tag:          tag,
		Label:        label,
		UserPresence: true,
	})
	if err != nil {
		t.Fatalf("error creating key: %v", err)
	}

	k.LAContext = &LAContext{
		LocalizedReason: "testing",
	}

	digest := sha256.Sum256([]byte(digestInput))

	got, err := k.Sign(nil, digest[:], nil)
	if err != nil {
		t.Errorf("Key.Sign() error = %v, wantErr %v", err, false)
		return
	}
	if !ecdsa.VerifyASN1(k.PublicKey, digest[:], got) {
		t.Errorf("invalid signature")
	}
}
