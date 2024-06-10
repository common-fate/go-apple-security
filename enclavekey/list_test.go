package enclavekey

import (
	"bytes"
	"errors"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestList(t *testing.T) {
	type args struct {
		input ListInput
	}
	tests := []struct {
		name       string
		createKeys []CreateInput
		args       args
		wantCount  int
		wantErr    bool
	}{
		{
			name: "empty_list",
			args: args{
				input: ListInput{
					Tag: "com.example.goapplesecurity.test.empty",
				},
			},
			wantCount: 0,
		},
		{
			name: "ok",
			createKeys: []CreateInput{
				{
					Tag: "com.example.goapplesecurity.test.listkey",
				},
				{
					Tag: "com.example.goapplesecurity.test.listkey",
				},
			},
			args: args{
				input: ListInput{
					Tag: "com.example.goapplesecurity.test.listkey",
				},
			},
			wantCount: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// delete any existing keys
			_, err := Delete(DeleteInput{
				Tag:   tt.args.input.Tag,
				Label: tt.args.input.Label,
			})
			if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
				t.Fatalf("error deleting existing keys: %v", err)
			}

			for _, c := range tt.createKeys {
				// create a new key based on the provided input
				_, err := Create(c)
				if err != nil {
					t.Fatalf("error creating key: %v", err)
				}
			}

			got, err := List(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.wantCount {
				t.Errorf("wanted %v keys but got %v", tt.wantCount, len(got))
			}
		})
	}
}

func TestListReturnsAttributes(t *testing.T) {
	tag := "com.example.goapplesecurity.test.listkey"
	label := "example test label"

	// delete any existing keys
	_, err := Delete(DeleteInput{
		Tag: tag,
	})
	if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
		t.Fatalf("error deleting existing keys: %v", err)
	}

	created, err := Create(CreateInput{
		Tag:   tag,
		Label: label,
	})
	if err != nil {
		t.Fatalf("error creating key: %v", err)
	}

	got, err := List(ListInput{
		Tag: tag,
	})
	if err != nil {
		t.Fatalf("error listing keys: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("wanted 1 keys but got %v", len(got))
	}

	gotKey := got[0]

	if gotKey.Label != created.Label {
		t.Errorf("got label = %s, want = %s", gotKey.Label, created.Label)
	}

	if gotKey.Tag != created.Tag {
		t.Errorf("got tag = %s, want = %s", gotKey.Tag, created.Tag)
	}

	if !gotKey.PublicKey.Equal(created.PublicKey) {
		t.Errorf("retrieved public key was not equal to public key from New(), got = %+v, want = %+v", gotKey.PublicKey, created.PublicKey)
	}

	if gotKey.ApplicationLabel == nil {
		t.Errorf("got nil ApplicationLabel")
	}

	if !bytes.Equal(gotKey.ApplicationLabel, created.ApplicationLabel) {
		t.Errorf("got ApplicationLabel = %x, want = %x", gotKey.ApplicationLabel, created.ApplicationLabel)
	}
}
