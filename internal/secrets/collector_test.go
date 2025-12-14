package secrets

import (
	"reflect"
	"testing"

	"github.com/dirathea/sstart/internal/provider"
)

func Test_keyMapping(t *testing.T) {
	type args struct {
		in   []provider.KeyValue
		keys map[string]string
	}
	tests := []struct {
		name string
		args args
		want []provider.KeyValue
	}{
		{
			name: "select",
			args: args{
				in: []provider.KeyValue{
					{"API_KEY", "test-api-key"},
					{"DATABASE_URL", "postgres://localhost:5432/testdb"},
					{"OTHER_VALUE", "should-not-appear"},
				},
				keys: map[string]string{
					"API_KEY": "==", // Keep same name
				},
			},
			want: []provider.KeyValue{
				{"API_KEY", "test-api-key"},
			},
		},
		{
			name: "rename",
			args: args{
				in: []provider.KeyValue{
					{"API_KEY", "test-api-key"},
					{"DATABASE_URL", "postgres://localhost:5432/testdb"},
					{"OTHER_VALUE", "should-not-appear"},
				},
				keys: map[string]string{
					"DATABASE_URL": "DB_URL",
				},
			},
			want: []provider.KeyValue{
				{"DB_URL", "postgres://localhost:5432/testdb"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyMapping(tt.args.in, tt.args.keys); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyMapping() = %v, want %v", got, tt.want)
			}
		})
	}
}
