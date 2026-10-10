// Package access defines transport-independent resource authorization policies
// shared by the server's API and HTTP adapters.
package access

import "github.com/usememos/memos/store"

// MemoReadDenial describes why a memo read was rejected.
type MemoReadDenial int

const (
	// MemoReadDenialNone means the read is allowed.
	MemoReadDenialNone MemoReadDenial = iota
	// MemoReadDenialNotFound hides missing, archived, and invalid memo state.
	MemoReadDenialNotFound
	// MemoReadDenialUnauthenticated means the resource requires a signed-in user.
	MemoReadDenialUnauthenticated
	// MemoReadDenialPermission means the signed-in user cannot read the resource.
	MemoReadDenialPermission
)

// MemoReadClass describes whether the resource is anonymously readable.
type MemoReadClass int

const (
	// MemoReadClassPrivate is for author, authenticated, member, or share-token reads.
	MemoReadClassPrivate MemoReadClass = iota
	// MemoReadClassPublic is for resources currently readable without credentials.
	MemoReadClassPublic
)

// MemoReadDecision is the outcome of evaluating memo read access.
type MemoReadDecision struct {
	Denial MemoReadDenial
	Class  MemoReadClass
}

// MemoReadContext contains the fully resolved authorization context for one
// memo. Relations never contribute authorization; callers evaluate each
// relation endpoint independently.
type MemoReadContext struct {
	Memo              *store.Memo
	Viewer            *store.User
	AllowAnonymous    bool
	SharedMemoID      *int32
	CreatorValid      bool
	SpaceValid        bool
	ViewerSpaceMember bool
}

// Allowed reports whether the read is permitted.
func (d MemoReadDecision) Allowed() bool {
	return d.Denial == MemoReadDenialNone
}

// IsActiveUser reports whether the user exists and is in the normal lifecycle
// state, which every authenticated authorization decision requires.
func IsActiveUser(user *store.User) bool {
	return user != nil && user.RowStatus == store.Normal
}

// IsInstanceAdmin reports whether the user is an active application ADMIN.
// Instance administration covers instance concerns only (settings, accounts,
// storage). It grants no access to memos, attachments, reactions, or Spaces:
// content is private to its author and to members of the Space it is in, so
// content authorization must never consult this.
func IsInstanceAdmin(user *store.User) bool {
	return IsActiveUser(user) && user.Role == store.RoleAdmin
}

// CanManageMemo reports whether the actor may perform author-level operations
// on the memo: only its active author.
func CanManageMemo(actor *store.User, memo *store.Memo) bool {
	return memo != nil && owns(actor, memo.CreatorID)
}

// CanManageAttachment reports whether the actor may mutate an attachment row
// directly: only its active owner.
func CanManageAttachment(actor *store.User, attachment *store.Attachment) bool {
	return attachment != nil && owns(actor, attachment.CreatorID)
}

func owns(actor *store.User, creatorID int32) bool {
	return IsActiveUser(actor) && actor.ID == creatorID
}

// CheckMemoReadContext evaluates access to exactly one memo. Unknown audience,
// invalid lifecycle state, and a missing or invalid creator fail closed. A
// dangling placement only invalidates SPACE reads; other audiences
// remain memo-local. A share applies only to the exact memo and never to either
// endpoint of a relation.
func CheckMemoReadContext(ctx MemoReadContext) MemoReadDecision {
	memo := ctx.Memo
	if memo == nil || !ctx.CreatorValid {
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}
	if memo.Visibility != store.Public && memo.Visibility != store.Protected && memo.Visibility != store.Private && memo.Visibility != store.SpaceAudience {
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}
	if memo.Visibility == store.SpaceAudience && (memo.SpaceID == nil || !ctx.SpaceValid) {
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}

	if memo.RowStatus != store.Normal && memo.RowStatus != store.Archived {
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}

	viewerActive := IsActiveUser(ctx.Viewer)
	viewerIsAuthor := viewerActive && ctx.Viewer.ID == memo.CreatorID
	if memo.RowStatus == store.Archived && !viewerIsAuthor {
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}

	shareApplies := ctx.SharedMemoID != nil && memo.ID == *ctx.SharedMemoID && memo.Visibility != store.SpaceAudience
	if shareApplies {
		return MemoReadDecision{Class: MemoReadClassPrivate}
	}

	switch memo.Visibility {
	case store.Public:
		if ctx.AllowAnonymous {
			return MemoReadDecision{Class: MemoReadClassPublic}
		}
		if viewerActive {
			return MemoReadDecision{Class: MemoReadClassPrivate}
		}
		return MemoReadDecision{Denial: MemoReadDenialUnauthenticated}
	case store.Protected:
		if viewerActive {
			return MemoReadDecision{Class: MemoReadClassPrivate}
		}
		return MemoReadDecision{Denial: MemoReadDenialUnauthenticated}
	case store.Private:
		if !viewerActive {
			return MemoReadDecision{Denial: MemoReadDenialUnauthenticated}
		}
		if !viewerIsAuthor {
			return MemoReadDecision{Denial: MemoReadDenialPermission}
		}
		return MemoReadDecision{Class: MemoReadClassPrivate}
	case store.SpaceAudience:
		if !viewerActive {
			return MemoReadDecision{Denial: MemoReadDenialUnauthenticated}
		}
		if ctx.ViewerSpaceMember {
			return MemoReadDecision{Class: MemoReadClassPrivate}
		}
		return MemoReadDecision{Denial: MemoReadDenialPermission}
	default:
		return MemoReadDecision{Denial: MemoReadDenialNotFound}
	}
}
