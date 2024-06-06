package keychain

import "testing"

func TestGenericPassword_AddRemove(t *testing.T) {
	type fields struct {
		Account string
		Service string
		Data    []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Account: "foo",
				Service: "bar",
				Data:    []byte("hello"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &GenericPassword{
				Account: tt.fields.Account,
				Service: tt.fields.Service,
				Data:    tt.fields.Data,
			}

			// remove any existing keychain item,
			// otherwise Add will always fail.
			err := p.Remove()
			if err != nil {
				t.Fatal(err)
			}

			if err := p.Add(); (err != nil) != tt.wantErr {
				t.Errorf("GenericPassword.Add() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
