package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// DecodeSecretJSONValue parses a secret payload into a generic value, keeping
// numbers as json.Number so that their original text survives the round trip.
//
// Unlike DecodeSecretJSON it accepts any JSON document, not only an object,
// because a JSON pointer may address an array element or a bare scalar.
func DecodeSecretJSONValue(data []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var parsed interface{}
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}

	// json.Unmarshal rejects trailing content; Decoder does not. Keep the
	// stricter behaviour so a payload that is only partly JSON still falls
	// back to being treated as a plain value.
	if dec.More() {
		return nil, fmt.Errorf("unexpected trailing content after JSON value")
	}

	return parsed, nil
}

// DecodeSecretJSON parses a secret payload into a generic map, keeping numbers
// as json.Number so that their original text survives the round trip.
//
// Decoding into interface{} the usual way turns every JSON number into a
// float64, and large integers such as Unix timestamps then stringify as
// scientific notation.
func DecodeSecretJSON(data []byte) (map[string]interface{}, error) {
	parsed, err := DecodeSecretJSONValue(data)
	if err != nil {
		return nil, err
	}

	object, ok := parsed.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("secret payload is not a JSON object")
	}

	return object, nil
}

// StringifyValue renders a decoded JSON value as the string that goes into an
// environment variable.
//
// Scalars keep their literal JSON form. Arrays and objects are re-encoded as
// JSON so the value stays parseable by the receiving process; Go's default
// formatting would emit map[k:v] instead.
func StringifyValue(v interface{}) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case json.Number:
		return value.String()
	case bool:
		return strconv.FormatBool(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	default:
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
		return fmt.Sprintf("%v", value)
	}
}
