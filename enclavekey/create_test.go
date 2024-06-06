package enclavekey

import (
	"testing"
)

func TestCreateKey(t *testing.T) {
	type args struct {
		opts CreateInput
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				opts: CreateInput{
					Tag: "com.example.goapplesecurity.test.key",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Create(tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.PublicKey == nil {
				t.Fatal("returned key had no public key")
			}
		})
	}
}
