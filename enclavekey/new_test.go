package enclavekey

import (
	"testing"
)

func TestNewKey(t *testing.T) {
	type args struct {
		opts NewInput
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				opts: NewInput{
					Tag: "com.example.goapplesecurity.test.key",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Public == nil {
				t.Fatal("returned key had no public key")
			}
		})
	}
}
