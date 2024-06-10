package keychain

import (
	"errors"
	"reflect"
	"testing"

	applesecurity "github.com/common-fate/go-apple-security"
)

func TestGetGenericPassword(t *testing.T) {
	type args struct {
		input GetGenericPasswordInput
		data  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *GenericPassword
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				input: GetGenericPasswordInput{
					Service: "test",
					Account: "example test account",
				},
				data: []byte("hello"),
			},
			want: &GenericPassword{
				Account: "example test account",
				Service: "test",
				Data:    []byte("hello"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeleteGenericPasswords(DeleteGenericPasswordsInput{
				Account: tt.args.input.Account,
				Service: tt.args.input.Service,
			})
			if err != nil && !errors.Is(err, applesecurity.ErrItemNotFound) {
				t.Fatal(err)
			}

			err = AddGenericPassword(GenericPassword{
				Account: tt.args.input.Account,
				Service: tt.args.input.Service,
				Data:    tt.args.data,
			})
			if err != nil {
				t.Fatal(err)
			}

			got, err := GetGenericPassword(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetGenericPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetGenericPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
