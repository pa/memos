package store

import (
	"context"
	"log/slog"

	"github.com/pkg/errors"
)

// EnforcePrivateMemoVisibility narrows every PUBLIC or PROTECTED memo to
// PRIVATE. A private instance runs it at startup so content that was visible
// to everyone becomes visible to its author only. It is idempotent.
func (s *Store) EnforcePrivateMemoVisibility(ctx context.Context) error {
	memos, err := s.ListMemos(ctx, &FindMemo{
		VisibilityList: []Visibility{Public, Protected},
		ExcludeContent: true,
	})
	if err != nil {
		return errors.Wrap(err, "failed to list public memos")
	}
	private := Private
	for _, memo := range memos {
		if err := s.UpdateMemo(ctx, &UpdateMemo{ID: memo.ID, Visibility: &private}); err != nil {
			return errors.Wrapf(err, "failed to make memo %d private", memo.ID)
		}
	}
	if len(memos) > 0 {
		slog.Info("private instance: narrowed memos to PRIVATE", "count", len(memos))
	}
	return nil
}
