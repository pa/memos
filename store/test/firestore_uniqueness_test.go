package test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/usememos/memos/store"
)

// TestFirestoreUniquenessHoldsWithoutIndexes checks that uniqueness does not
// depend on indexes, which a runtime identity may be unable to create. It
// drops every secondary index, then races duplicate usernames and memo UIDs.
func TestFirestoreUniquenessHoldsWithoutIndexes(t *testing.T) {
	if getDriverFromEnv() != "firestore" {
		t.Skip("Firestore-specific check")
	}
	ctx := context.Background()
	ts := NewTestingStore(ctx, t)
	defer ts.Close()
	require.NoError(t, firestoreRaw(t, ts).DropIndexes(ctx))

	const racers = 6
	var wg sync.WaitGroup
	results := make(chan error, racers)
	for range racers {
		wg.Go(func() {
			_, err := ts.CreateUser(ctx, &store.User{Username: "same-name", Role: store.RoleUser, PasswordHash: "hash"})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else {
			require.ErrorIs(t, err, store.ErrUsernameTaken)
		}
	}
	require.Equal(t, 1, created, "exactly one user may own a username")

	owner, err := ts.GetUser(ctx, &store.FindUser{Username: new("same-name")})
	require.NoError(t, err)
	_, err = ts.CreateMemo(ctx, &store.Memo{UID: "dup-uid", CreatorID: owner.ID, Content: "a", Visibility: store.Private})
	require.NoError(t, err)
	_, err = ts.CreateMemo(ctx, &store.Memo{UID: "dup-uid", CreatorID: owner.ID, Content: "b", Visibility: store.Private})
	require.ErrorContains(t, err, "UNIQUE constraint failed")

	// Renaming frees the old name and claims the new one.
	renamed := "renamed"
	_, err = ts.UpdateUser(ctx, &store.UpdateUser{ID: owner.ID, Username: &renamed})
	require.NoError(t, err)
	_, err = ts.CreateUser(ctx, &store.User{Username: "same-name", Role: store.RoleUser, PasswordHash: "hash"})
	require.NoError(t, err, "the old username must be free after a rename")

	// Deleting a memo frees its UID.
	memos, err := ts.ListMemos(ctx, &store.FindMemo{UID: new("dup-uid")})
	require.NoError(t, err)
	require.NoError(t, ts.DeleteMemo(ctx, &store.DeleteMemo{ID: memos[0].ID}))
	_, err = ts.CreateMemo(ctx, &store.Memo{UID: "dup-uid", CreatorID: owner.ID, Content: "c", Visibility: store.Private})
	require.NoError(t, err, "a deleted memo's UID must be reusable")

	for i := range 3 {
		_, err := ts.CreateSpace(ctx, &store.Space{UID: fmt.Sprintf("sp-%d", i%2), Title: "x"}, owner.ID)
		if i == 2 {
			require.ErrorIs(t, err, store.ErrSpaceAlreadyExists)
		} else {
			require.NoError(t, err)
		}
	}
}
