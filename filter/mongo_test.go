package filter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type fakeResolver struct{}

func (fakeResolver) UserIDByUsername(_ context.Context, username string) (int32, bool, error) {
	if username == "alice" {
		return 7, true, nil
	}
	return 0, false, nil
}

func (fakeResolver) SpaceIDByUID(_ context.Context, uid string) (int32, bool, error) {
	if uid == "team" {
		return 3, true, nil
	}
	return 0, false, nil
}

func TestCompileToMongo(t *testing.T) {
	engine, err := NewEngine(NewSchema())
	require.NoError(t, err)
	ctx := context.Background()
	opts := MongoRenderOptions{Resolver: fakeResolver{}}

	cases := []struct {
		filter string
		want   bson.M
	}{
		{`pinned`, bson.M{"pinned": true}},
		{`!pinned`, bson.M{"$nor": bson.A{bson.M{"pinned": true}}}},
		{`visibility == "PUBLIC"`, bson.M{"visibility": bson.M{"$eq": "PUBLIC"}}},
		{`creator == "users/alice"`, bson.M{"creator_id": int32(7)}},
		{`creator == "users/nobody"`, MongoNoMatch()},
		{`space == "spaces/team"`, bson.M{"space_id": int32(3)}},
		{`space == null`, bson.M{"space_id": nil}},
		{`"work" in tags`, bson.M{"tags": "work"}},
		{`tag in ["a", "b"]`, bson.M{"tags": bson.M{"$in": bson.A{"a", "b"}}}},
		{`has_task_list == false`, bson.M{"has_task_list": bson.M{"$ne": true}}},
		{`content.contains("a.b")`, bson.M{"content": bson.M{"$regex": `a\.b`, "$options": "i"}}},
		{`created_ts >= timestamp(100)`, bson.M{"created_ts": bson.M{"$gte": int64(100)}}},
		{`pinned && visibility == "PRIVATE"`, bson.M{"$and": bson.A{bson.M{"pinned": true}, bson.M{"visibility": bson.M{"$eq": "PRIVATE"}}}}},
		{`pinned || false`, bson.M{"pinned": true}},
	}
	for _, tc := range cases {
		got, err := engine.CompileToMongo(ctx, tc.filter, opts)
		require.NoError(t, err, tc.filter)
		require.Equal(t, tc.want, got, tc.filter)
	}

	_, err = engine.CompileToMongo(ctx, `space != "spaces/team"`, opts)
	require.Error(t, err, "space supports only equality, like the SQL renderer")
}
