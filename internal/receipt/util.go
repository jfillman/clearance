package receipt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/jfillman/clearance/internal/token"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// decode reads DSSE base64: standard or URL-safe, padded or not.
func decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: payload is not base64", token.ErrMalformed)
}
