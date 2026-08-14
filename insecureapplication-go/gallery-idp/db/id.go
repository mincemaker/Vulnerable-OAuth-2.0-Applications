package db

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a 24-hex-char id, cosmetically similar to a Mongo ObjectId
// (this app has no other structural dependency on Mongo's id format).
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
