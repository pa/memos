package test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/usememos/memos/store"
)

// TestFirestoreInvitationNeverOutlivesDeletedParent races invitation creation
// against user and Space deletion. SQL drivers serialize these with row locks
// (see space_parent_lock_test.go); Firestore aborts the conflicting
// transaction and retries it, so after both finish no invitation may remain
// for a deleted user or Space.
func TestFirestoreInvitationNeverOutlivesDeletedParent(t *testing.T) {
	if getDriverFromEnv() != "firestore" {
		t.Skip("Firestore-specific concurrency check")
	}
	ctx := context.Background()
	ts := NewTestingStore(ctx, t)
	defer ts.Close()

	owner, err := ts.CreateUser(ctx, &store.User{Username: "race-owner", Role: store.RoleUser, PasswordHash: "hash"})
	require.NoError(t, err)

	for i := range 15 {
		target, err := ts.CreateUser(ctx, &store.User{Username: fmt.Sprintf("race-target-%d", i), Role: store.RoleUser, PasswordHash: "hash"})
		require.NoError(t, err)
		space, err := ts.CreateSpace(ctx, &store.Space{UID: fmt.Sprintf("race-space-%d", i), Title: "Race"}, owner.ID)
		require.NoError(t, err)

		var wg sync.WaitGroup
		deleteSpace := i%2 == 0
		wg.Go(func() {
			if deleteSpace {
				_, _ = ts.DeleteSpace(ctx, &store.DeleteSpace{ID: space.ID, ActorUserID: owner.ID})
			} else {
				_, _ = ts.DeleteUser(ctx, &store.DeleteUser{ID: target.ID})
			}
		})
		wg.Go(func() {
			_, _ = ts.CreateSpaceInvitation(ctx, &store.SpaceInvitation{SpaceID: space.ID, UserID: target.ID, Role: store.SpaceMemberRoleUser}, owner.ID)
		})
		wg.Wait()

		if deleteSpace {
			require.Zero(t, countFirestoreDocs(ctx, t, ts, "space_member", map[string]any{"space_id": space.ID}),
				"round %d: a deleted Space must not keep memberships or invitations", i)
		} else {
			require.Zero(t, countFirestoreDocs(ctx, t, ts, "space_member", map[string]any{"user_id": target.ID}),
				"round %d: a deleted user must not keep invitations", i)
		}
	}
}
