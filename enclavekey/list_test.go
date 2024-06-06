package enclavekey

import (
	"errors"
	"testing"
)

func TestList(t *testing.T) {
	type args struct {
		input GetInput
	}
	tests := []struct {
		name    string
		args    args
		want    *Key
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				input: GetInput{
					Tag: "com.example.goapplesecurity.test.key",
				},
			},
		},
		{
			name: "with_label",
			args: args{
				input: GetInput{
					Tag:   "com.example.goapplesecurity.test.key_with_label",
					Label: "test label",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// delete any existing keys
			_, err := Delete(DeleteInput{
				Tag:   tt.args.input.Tag,
				Label: tt.args.input.Label,
			})
			if err != nil && !errors.Is(err, ErrNotFound) {
				t.Fatalf("error deleting existing keys: %v", err)
			}

			// create a new key based on the provided input
			key, err := New(NewInput{
				Tag:   tt.args.input.Tag,
				Label: tt.args.input.Label,
			})
			if err != nil {
				t.Fatalf("error creating key: %v", err)
			}

			got, err := Get(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !got.Public.Equal(key.Public) {
				t.Errorf("retrieved public key was not equal to public key from New(), got = %+v, want = %+v", got.Public, key.Public)
			}
		})
	}
}
