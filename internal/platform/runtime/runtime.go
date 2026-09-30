package runtime

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Clock struct{}

func (Clock) Now() time.Time { return time.Now().UTC() }

type IDs struct{}

func (IDs) NewID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(value[:])
}
