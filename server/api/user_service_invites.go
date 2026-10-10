package api

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	apipb "github.com/usememos/memos/proto/gen/api"
	"github.com/usememos/memos/server/auth"
	"github.com/usememos/memos/store"
)

const (
	defaultInviteTTLHours = 72
	maxInviteTTLHours     = int32(auth.InviteTokenMaxDuration / time.Hour)
)

// CreateUserInvite issues a signed invite for one username. Only an instance
// administrator may invite; the invite lets the holder sign up even when open
// registration is closed.
func (s *APIService) CreateUserInvite(ctx context.Context, request *apipb.CreateUserInviteRequest) (*apipb.CreateUserInviteResponse, error) {
	currentUser, err := s.fetchCurrentUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get current user")
	}
	if currentUser == nil {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}
	if currentUser.Role != store.RoleAdmin || currentUser.RowStatus != store.Normal {
		return nil, status.Errorf(codes.PermissionDenied, "permission denied")
	}
	if err := validateWritableUsername(request.Username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	ttlHours := request.TtlHours
	if ttlHours == 0 {
		ttlHours = defaultInviteTTLHours
	}
	if ttlHours < 0 || ttlHours > maxInviteTTLHours {
		return nil, status.Errorf(codes.InvalidArgument, "ttl_hours must be between 1 and %d", maxInviteTTLHours)
	}
	existing, err := s.Store.GetUser(ctx, &store.FindUser{Username: &request.Username})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check username")
	}
	if existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "username is already taken")
	}
	token, expiresAt, err := auth.GenerateInviteToken(request.Username, currentUser.ID, time.Duration(ttlHours)*time.Hour, []byte(s.Secret))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create invite")
	}
	return &apipb.CreateUserInviteResponse{
		InviteToken: token,
		ExpireTime:  timestamppb.New(expiresAt),
	}, nil
}
