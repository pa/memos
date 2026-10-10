package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInviteTokenRoundTrip(t *testing.T) {
	secret := []byte("invite-secret")
	token, expiresAt, err := GenerateInviteToken(" alice ", 1, time.Hour, secret)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(time.Hour), expiresAt, 5*time.Second)

	claims, err := ParseInviteToken(token, secret)
	require.NoError(t, err)
	require.Equal(t, "alice", claims.Username)
	require.EqualValues(t, 1, claims.InvitedBy)

	_, err = ParseInviteToken(token, []byte("other-secret"))
	require.Error(t, err, "a token signed with another secret is rejected")
}

func TestInviteTokenRejectsOtherTokenKinds(t *testing.T) {
	secret := []byte("invite-secret")
	refresh, _, err := GenerateRefreshToken(1, "tid", secret)
	require.NoError(t, err)
	_, err = ParseInviteToken(refresh, secret)
	require.Error(t, err, "a refresh token is not an invite")

	access, _, err := GenerateAccessTokenV2(1, "alice", "USER", "NORMAL", secret)
	require.NoError(t, err)
	_, err = ParseInviteToken(access, secret)
	require.Error(t, err, "an access token is not an invite")
}

func TestInviteTokenLifetimeBounds(t *testing.T) {
	secret := []byte("invite-secret")
	_, _, err := GenerateInviteToken("alice", 1, 0, secret)
	require.Error(t, err)
	_, _, err = GenerateInviteToken("alice", 1, InviteTokenMaxDuration+time.Hour, secret)
	require.Error(t, err)
	_, _, err = GenerateInviteToken(" ", 1, time.Hour, secret)
	require.Error(t, err)

	expired, _, err := GenerateInviteToken("alice", 1, time.Second, secret)
	require.NoError(t, err)
	time.Sleep(2100 * time.Millisecond)
	_, err = ParseInviteToken(expired, secret)
	require.Error(t, err, "an expired invite is rejected")
}
