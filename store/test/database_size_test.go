package test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDatabaseSize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := NewTestingStore(ctx, t)
	defer ts.Close()

	size, err := ts.GetDriver().GetDatabaseSize(ctx)
	require.NoError(t, err)
	if getDriverFromEnv() == "firestore" {
		require.Equal(t, int64(-1), size, "Firestore cannot report a database size")
		return
	}
	require.Greater(t, size, int64(0), "expected database size > 0")
}
