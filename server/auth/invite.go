package auth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

const (
	// InviteTokenAudienceName is the audience claim for user invite tokens.
	InviteTokenAudienceName = "user.invite"

	// InviteTokenMaxDuration bounds how long an invite link stays valid.
	InviteTokenMaxDuration = 30 * 24 * time.Hour
)

// InviteTokenClaims authorize exactly one sign-up for the bound username.
// The token cannot be reused once the username exists, because usernames are
// unique; it cannot be revoked before it expires, so lifetimes stay short.
type InviteTokenClaims struct {
	Type      string `json:"type"` // "invite"
	Username  string `json:"username"`
	InvitedBy int32  `json:"invited_by"`
	jwt.RegisteredClaims
}

// GenerateInviteToken signs an invite for username that expires after ttl.
func GenerateInviteToken(username string, invitedBy int32, ttl time.Duration, secret []byte) (string, time.Time, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", time.Time{}, errors.New("invite requires a username")
	}
	if ttl <= 0 || ttl > InviteTokenMaxDuration {
		return "", time.Time{}, errors.Errorf("invite lifetime must be between 1s and %s", InviteTokenMaxDuration)
	}
	now := time.Now()
	expiresAt := now.Add(ttl)
	claims := &InviteTokenClaims{
		Type:      "invite",
		Username:  username,
		InvitedBy: invitedBy,
		Issuer:    Issuer,
		Audience:  jwt.ClaimStrings{InviteTokenAudienceName},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = KeyID
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", time.Time{}, errors.Wrap(err, "failed to sign invite token")
	}
	return signed, expiresAt, nil
}

// ParseInviteToken validates an invite token and returns its claims.
func ParseInviteToken(tokenString string, secret []byte) (*InviteTokenClaims, error) {
	claims := &InviteTokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, verifyJWTKeyFunc(secret),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(InviteTokenAudienceName),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if claims.Type != "invite" || claims.Username == "" {
		return nil, errors.New("invalid invite token")
	}
	return claims, nil
}
