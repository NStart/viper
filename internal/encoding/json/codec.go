package json

import "encoding/json"

type Codec struct{}

func (Codec) Encode(v map[string]any) ([]byte, error) {
	return json.MarshalIndent(v ,)
}