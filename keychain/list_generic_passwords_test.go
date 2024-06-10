package keychain

import (
	"errors"
	"reflect"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestListGenericPasswords(t *testing.T) {
	type args struct {
		input ListGenericPasswordsInput
	}
	tests := []struct {
		name    string
		args    args
		insert  []GenericPassword
		want    []GenericPassword
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				input: ListGenericPasswordsInput{
					Service: "foo",
				},
			},
			insert: []GenericPassword{
				{
					Account: "test1",
					Service: "foo",
					Data:    []byte("hello"),
				},
				{
					Account: "test2",
					Service: "foo",
					Data:    []byte("hello2"),
				},
			},
			want: []GenericPassword{
				{
					Account: "test1",
					Service: "foo",
					Data:    []byte("hello"),
				},
				{
					Account: "test2",
					Service: "foo",
					Data:    []byte("hello2"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeleteGenericPasswords(DeleteGenericPasswordsInput{
				Service: tt.args.input.Service,
			})
			if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
				t.Fatal(err)
			}

			for _, p := range tt.insert {
				err = AddGenericPassword(p)
				if err != nil {
					t.Fatal(err)
				}
			}

			got, err := ListGenericPasswords(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListGenericPasswords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListGenericPasswords() = %v, want %v", got, tt.want)
			}
		})
	}
}
