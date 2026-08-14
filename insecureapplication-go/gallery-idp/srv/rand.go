package srv

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"strconv"
)

// weakCode / weakToken deliberately reproduce the original gallery's
// Math.floor(Math.random() * (100000-1) + 1) -- a decimal string in [1,99999],
// drawn from a non-cryptographic PRNG. This narrow value space is what makes
// PoC3 (bruteforce authorization codes) and the attacker app's
// /guessauthzcode and /guessaccesstokenatresourceserver routes succeed; see
// doc/OAuth2_PoC_Verification_Report.md.
func weakCode() string {
	return strconv.Itoa(mrand.Intn(99999) + 1)
}

func weakToken() string {
	return strconv.Itoa(mrand.Intn(99999) + 1)
}

// newSessionID and newTransactionID use crypto/rand: the *value space* of
// OAuth codes/tokens is the deliberately weak part of this app, not the
// session/transaction id, which isn't part of any documented PoC.
func newOpaqueID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
