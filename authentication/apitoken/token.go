package apitoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"hash"
	"strings"
)

const (
	idBytes      = 16
	idChars      = 26
	secretBytes  = 32
	secretChars  = 52
	minPrefix    = 2
	maxPrefix    = 16
	minPepper    = 32
	maxPepper    = 1024
	maxTokenSize = maxPrefix + 1 + idChars + 1 + secretChars

	digestDomain = "go-auth/apitoken/v1\x00"
)

// encoding is lowercase RFC 4648 base32 without padding. Its alphabet excludes
// the "_" separator so tokens split unambiguously.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func validPrefix(prefix string) bool {
	if len(prefix) < minPrefix || len(prefix) > maxPrefix {
		return false
	}
	for index := range len(prefix) {
		c := prefix[index]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && index > 0:
		default:
			return false
		}
	}
	return true
}

// ValidID reports whether id has the canonical API token ID form.
func ValidID(id string) bool {
	return canonical(id, idChars, idBytes)
}

func canonical(value string, chars, size int) bool {
	if len(value) != chars {
		return false
	}
	raw, err := encoding.DecodeString(value)
	if err != nil || len(raw) != size {
		return false
	}
	return encoding.EncodeToString(raw) == value
}

func formatToken(prefix string, id string, secret []byte) string {
	return prefix + "_" + id + "_" + encoding.EncodeToString(secret)
}

// hasPrefix reports whether token is addressed to an authenticator with prefix.
func hasPrefix(token string, prefix string) bool {
	return strings.HasPrefix(token, prefix+"_")
}

// parseToken splits a token addressed to prefix and returns its ID. It never
// includes token material in errors; callers map failure to a fixed error.
func parseToken(token string, prefix string) (string, bool) {
	if len(token) != len(prefix)+1+idChars+1+secretChars || !hasPrefix(token, prefix) {
		return "", false
	}
	rest := token[len(prefix)+1:]
	if rest[idChars] != '_' {
		return "", false
	}
	id, secret := rest[:idChars], rest[idChars+1:]
	if !canonical(id, idChars, idBytes) || !canonical(secret, secretChars, secretBytes) {
		return "", false
	}
	return id, true
}

// digest returns HMAC-SHA256(pepper, domain || token) when a pepper is
// configured and SHA-256(domain || token) otherwise. The whole token is
// hashed so a digest is bound to its prefix and ID.
func digest(pepper []byte, token string) [32]byte {
	var h hash.Hash
	if len(pepper) > 0 {
		h = hmac.New(sha256.New, pepper)
	} else {
		h = sha256.New()
	}
	h.Write([]byte(digestDomain))
	h.Write([]byte(token))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// digestsEqual compares digests in constant time.
func digestsEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func zeroDigest(value [32]byte) bool {
	return digestsEqual(value, [32]byte{})
}
