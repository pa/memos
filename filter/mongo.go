package filter

import (
	"context"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// MongoResolver resolves the references a filter makes to other collections.
// The Firestore store driver implements it; the filter package stays unaware
// of the store.
type MongoResolver interface {
	// UserIDByUsername returns the id of the user with the username.
	UserIDByUsername(ctx context.Context, username string) (int32, bool, error)
	// SpaceIDByUID returns the id of the Space with the UID.
	SpaceIDByUID(ctx context.Context, uid string) (int32, bool, error)
}

// MongoRenderOptions configures Mongo rendering.
type MongoRenderOptions struct {
	Resolver MongoResolver
	// MemoPrefix is the path under which the joined memo document lives for
	// the attachment schema (for example "_memo."). Unused for memos.
	MemoPrefix string
}

// CompileToMongo compiles a filter into a MongoDB query document.
func (e *Engine) CompileToMongo(ctx context.Context, filter string, opts MongoRenderOptions) (bson.M, error) {
	program, err := e.Compile(ctx, filter)
	if err != nil {
		return nil, err
	}
	return program.RenderMongo(ctx, opts)
}

// RenderMongo converts the program into a MongoDB query document. An empty
// document matches everything; MongoNoMatch matches nothing.
func (p *Program) RenderMongo(ctx context.Context, opts MongoRenderOptions) (bson.M, error) {
	r := &mongoRenderer{ctx: ctx, schema: p.schema, opts: opts}
	result, err := r.render(p.condition)
	if err != nil {
		return nil, err
	}
	switch {
	case result.none:
		return MongoNoMatch(), nil
	case result.all:
		return bson.M{}, nil
	default:
		return result.doc, nil
	}
}

// MongoNoMatch is a query document that matches no document.
func MongoNoMatch() bson.M {
	return bson.M{"_id": bson.M{"$in": bson.A{}}}
}

type mongoResult struct {
	doc  bson.M
	all  bool
	none bool
}

type mongoRenderer struct {
	ctx    context.Context
	schema Schema
	opts   MongoRenderOptions
}

func mongoDoc(doc bson.M) mongoResult { return mongoResult{doc: doc} }

func (r *mongoRenderer) render(cond Condition) (mongoResult, error) {
	switch c := cond.(type) {
	case *LogicalCondition:
		left, err := r.render(c.Left)
		if err != nil {
			return mongoResult{}, err
		}
		right, err := r.render(c.Right)
		if err != nil {
			return mongoResult{}, err
		}
		if c.Operator == LogicalAnd {
			switch {
			case left.none || right.none:
				return mongoResult{none: true}, nil
			case left.all:
				return right, nil
			case right.all:
				return left, nil
			}
			return mongoDoc(bson.M{"$and": bson.A{left.doc, right.doc}}), nil
		}
		switch {
		case left.all || right.all:
			return mongoResult{all: true}, nil
		case left.none:
			return right, nil
		case right.none:
			return left, nil
		}
		return mongoDoc(bson.M{"$or": bson.A{left.doc, right.doc}}), nil
	case *NotCondition:
		child, err := r.render(c.Expr)
		if err != nil {
			return mongoResult{}, err
		}
		switch {
		case child.all:
			return mongoResult{none: true}, nil
		case child.none:
			return mongoResult{all: true}, nil
		}
		return mongoDoc(bson.M{"$nor": bson.A{child.doc}}), nil
	case *ConstantCondition:
		if c.Value {
			return mongoResult{all: true}, nil
		}
		return mongoResult{none: true}, nil
	case *FieldPredicateCondition:
		return r.renderPredicate(c.Field, true)
	case *ComparisonCondition:
		return r.renderComparison(c)
	case *InCondition:
		return r.renderIn(c)
	case *ElementInCondition:
		lit, err := expectLiteral(c.Element)
		if err != nil {
			return mongoResult{}, err
		}
		value, ok := lit.(string)
		if !ok {
			return mongoResult{}, errors.New("tags membership requires string literal")
		}
		return r.renderTagComprehension(c.Field, &EqualsPredicate{Value: value}, ComprehensionExists)
	case *TextMatchCondition:
		path, err := r.scalarPath(c.Field)
		if err != nil {
			return mongoResult{}, err
		}
		pattern := regexp.QuoteMeta(c.Value)
		switch c.Mode {
		case TextMatchPrefix:
			pattern = "^" + pattern
		case TextMatchSuffix:
			pattern += "$"
		default:
		}
		return mongoDoc(bson.M{path: bson.M{"$regex": pattern, "$options": "i"}}), nil
	case *RegexCondition:
		path, err := r.scalarPath(c.Field)
		if err != nil {
			return mongoResult{}, err
		}
		return mongoDoc(bson.M{path: bson.M{"$regex": c.Pattern}}), nil
	case *ListComprehensionCondition:
		return r.renderTagComprehension(c.Field, c.Predicate, c.Kind)
	default:
		return mongoResult{}, errors.Errorf("unsupported condition type %T", c)
	}
}

// scalarPath returns the document path backing a plain scalar field.
func (r *mongoRenderer) scalarPath(name string) (string, error) {
	field, ok := r.schema.Field(name)
	if !ok {
		return "", errors.Errorf("unknown field %q", name)
	}
	switch r.schema.Name {
	case "memo":
		switch field.Name {
		case "content", "creator_id", "created_ts", "updated_ts", "pinned", "visibility", "tags",
			"has_task_list", "has_link", "has_code", "has_incomplete_tasks", "has_location":
			return field.Name, nil
		default:
		}
	case "attachment":
		switch field.Name {
		case "filename", "memo_id":
			return field.Name, nil
		case "mime_type":
			return "type", nil
		case "create_time":
			return "created_ts", nil
		default:
		}
	default:
	}
	return "", errors.Errorf("field %q is not supported by the Firestore filter renderer", name)
}

func (r *mongoRenderer) renderPredicate(name string, want bool) (mongoResult, error) {
	path, err := r.scalarPath(name)
	if err != nil {
		return mongoResult{}, err
	}
	if want {
		return mongoDoc(bson.M{path: true}), nil
	}
	return mongoDoc(bson.M{path: bson.M{"$ne": true}}), nil
}

var mongoOps = map[ComparisonOperator]string{
	CompareEq: "$eq", CompareNeq: "$ne", CompareLt: "$lt", CompareLte: "$lte", CompareGt: "$gt", CompareGte: "$gte",
}

func (r *mongoRenderer) renderComparison(cond *ComparisonCondition) (mongoResult, error) {
	op, ok := mongoOps[cond.Operator]
	if !ok {
		return mongoResult{}, errors.Errorf("unsupported operator %s", cond.Operator)
	}
	switch left := cond.Left.(type) {
	case *FieldRef:
		field, ok := r.schema.Field(left.Name)
		if !ok {
			return mongoResult{}, errors.Errorf("unknown field %q", left.Name)
		}
		switch field.Kind {
		case FieldKindBoolColumn, FieldKindJSONBool, FieldKindJSONExists:
			value, err := expectBool(cond.Right)
			if err != nil {
				return mongoResult{}, err
			}
			switch cond.Operator {
			case CompareEq:
			case CompareNeq:
				value = !value
			default:
				return mongoResult{}, errors.Errorf("operator %s not supported for field %q", cond.Operator, field.Name)
			}
			return r.renderPredicate(field.Name, value)
		case FieldKindScalar:
			return r.renderScalarComparison(field, cond.Operator, op, cond.Right)
		default:
			return mongoResult{}, errors.Errorf("field %q does not support comparison", field.Name)
		}
	case *FunctionValue:
		return r.renderSize(left, op, cond.Right)
	case *FieldAccessorValue:
		return r.renderAccessor(left, op, cond.Right)
	default:
		return mongoResult{}, errors.New("comparison must start with a field reference or supported function")
	}
}

func (r *mongoRenderer) renderScalarComparison(field Field, operator ComparisonOperator, op string, right ValueExpr) (mongoResult, error) {
	lit, err := expectLiteral(right)
	if err != nil {
		return mongoResult{}, err
	}
	switch field.Name {
	case "creator":
		return r.renderCreator(operator, lit)
	case "space":
		return r.renderSpace(operator, lit)
	}
	path, err := r.scalarPath(field.Name)
	if err != nil {
		return mongoResult{}, err
	}
	if lit == nil {
		switch operator {
		case CompareEq:
			return mongoDoc(bson.M{path: nil}), nil
		case CompareNeq:
			return mongoDoc(bson.M{path: bson.M{"$ne": nil}}), nil
		default:
			return mongoResult{}, errors.Errorf("operator %s not supported for null comparison", operator)
		}
	}
	value, err := mongoScalar(field, lit)
	if err != nil {
		return mongoResult{}, err
	}
	return mongoDoc(bson.M{path: bson.M{op: value}}), nil
}

func mongoScalar(field Field, lit any) (any, error) {
	switch field.Type {
	case FieldTypeString:
		value, ok := lit.(string)
		if !ok {
			return nil, errors.Errorf("field %q expects string value", field.Name)
		}
		return value, nil
	case FieldTypeInt, FieldTypeTimestamp:
		value, err := toInt64(lit)
		if err != nil {
			return nil, errors.Wrapf(err, "field %q expects integer value", field.Name)
		}
		return value, nil
	default:
		return nil, errors.Errorf("unsupported data type %q for field %s", field.Type, field.Name)
	}
}

func (r *mongoRenderer) resolveCreator(lit any) (int32, bool, error) {
	name, ok := lit.(string)
	if !ok {
		return 0, false, errors.New("creator expects a string value")
	}
	username, ok := strings.CutPrefix(name, "users/")
	if !ok || r.opts.Resolver == nil {
		return 0, false, nil
	}
	return r.opts.Resolver.UserIDByUsername(r.ctx, username)
}

func (r *mongoRenderer) renderCreator(operator ComparisonOperator, lit any) (mongoResult, error) {
	id, found, err := r.resolveCreator(lit)
	if err != nil {
		return mongoResult{}, err
	}
	var match mongoResult
	if !found {
		match = mongoResult{none: true}
	} else if r.schema.Name == "attachment" {
		prefix := r.opts.MemoPrefix
		match = mongoDoc(bson.M{"$or": bson.A{
			bson.M{"memo_id": nil, "creator_id": id},
			bson.M{"memo_id": bson.M{"$ne": nil}, prefix + "creator_id": id},
		}})
	} else {
		match = mongoDoc(bson.M{"creator_id": id})
	}
	switch operator {
	case CompareEq:
		return match, nil
	case CompareNeq:
		if match.none {
			return mongoResult{all: true}, nil
		}
		return mongoDoc(bson.M{"$nor": bson.A{match.doc}}), nil
	default:
		return mongoResult{}, errors.Errorf("operator %s not supported for creator", operator)
	}
}

func (r *mongoRenderer) spacePath() (string, bson.M) {
	if r.schema.Name == "attachment" {
		return r.opts.MemoPrefix + "space_id", bson.M{"memo_id": bson.M{"$ne": nil}}
	}
	return "space_id", nil
}

func (r *mongoRenderer) renderSpace(operator ComparisonOperator, lit any) (mongoResult, error) {
	path, guard := r.spacePath()
	with := func(doc bson.M) mongoResult {
		if guard == nil {
			return mongoDoc(doc)
		}
		return mongoDoc(bson.M{"$and": bson.A{guard, doc}})
	}
	if lit == nil {
		switch operator {
		case CompareEq:
			if guard == nil {
				return mongoDoc(bson.M{path: nil}), nil
			}
			return mongoDoc(bson.M{"$or": bson.A{bson.M{"memo_id": nil}, bson.M{path: nil}}}), nil
		case CompareNeq:
			return with(bson.M{path: bson.M{"$ne": nil}}), nil
		default:
			return mongoResult{}, errors.Errorf("operator %s not supported for null comparison", operator)
		}
	}
	if operator != CompareEq {
		return mongoResult{}, errors.Errorf("operator %s not supported for space", operator)
	}
	name, ok := lit.(string)
	if !ok {
		return mongoResult{}, errors.New("space expects a string value")
	}
	uid, ok := strings.CutPrefix(name, "spaces/")
	if !ok || r.opts.Resolver == nil {
		return mongoResult{none: true}, nil
	}
	id, found, err := r.opts.Resolver.SpaceIDByUID(r.ctx, uid)
	if err != nil {
		return mongoResult{}, err
	}
	if !found {
		return mongoResult{none: true}, nil
	}
	return with(bson.M{path: id}), nil
}

func (r *mongoRenderer) renderIn(cond *InCondition) (mongoResult, error) {
	ref, ok := cond.Left.(*FieldRef)
	if !ok {
		return mongoResult{}, errors.New("IN operator requires a field on the left-hand side")
	}
	if ref.Name == "tag" {
		values := bson.A{}
		for _, v := range cond.Values {
			lit, err := expectLiteral(v)
			if err != nil {
				return mongoResult{}, err
			}
			s, ok := lit.(string)
			if !ok {
				return mongoResult{}, errors.New("tags must be compared with string literals")
			}
			values = append(values, s)
		}
		if len(values) == 0 {
			return mongoResult{none: true}, nil
		}
		return mongoDoc(bson.M{"tags": bson.M{"$in": values}}), nil
	}
	field, ok := r.schema.Field(ref.Name)
	if !ok {
		return mongoResult{}, errors.Errorf("unknown field %q", ref.Name)
	}
	if field.Kind != FieldKindScalar {
		return mongoResult{}, errors.Errorf("field %q does not support IN()", ref.Name)
	}
	if field.Name == "creator" || field.Name == "space" {
		return mongoResult{}, errors.Errorf("field %q does not support IN()", ref.Name)
	}
	path, err := r.scalarPath(field.Name)
	if err != nil {
		return mongoResult{}, err
	}
	values := bson.A{}
	for _, v := range cond.Values {
		lit, err := expectLiteral(v)
		if err != nil {
			return mongoResult{}, err
		}
		if field.Type == FieldTypeTimestamp {
			return mongoResult{}, errors.Errorf("field %q does not support IN() comparisons", field.Name)
		}
		value, err := mongoScalar(field, lit)
		if err != nil {
			return mongoResult{}, err
		}
		values = append(values, value)
	}
	return mongoDoc(bson.M{path: bson.M{"$in": values}}), nil
}

func (r *mongoRenderer) renderSize(fn *FunctionValue, op string, right ValueExpr) (mongoResult, error) {
	if fn.Name != "size" || len(fn.Args) != 1 {
		return mongoResult{}, errors.Errorf("unsupported function %s in comparison", fn.Name)
	}
	ref, ok := fn.Args[0].(*FieldRef)
	if !ok {
		return mongoResult{}, errors.New("size() argument must be a field")
	}
	field, ok := r.schema.ResolveAlias(ref.Name)
	if !ok {
		return mongoResult{}, errors.Errorf("unknown field %q", ref.Name)
	}
	value, err := expectNumericLiteral(right)
	if err != nil {
		return mongoResult{}, err
	}
	var expr bson.M
	switch {
	case field.Kind == FieldKindJSONList:
		expr = bson.M{"$size": bson.M{"$ifNull": bson.A{"$tags", bson.A{}}}}
	case field.Kind == FieldKindScalar && field.Type == FieldTypeString:
		path, err := r.scalarPath(field.Name)
		if err != nil {
			return mongoResult{}, err
		}
		expr = bson.M{"$strLenCP": bson.M{"$ifNull": bson.A{"$" + path, ""}}}
	default:
		return mongoResult{}, errors.Errorf("size() does not support field %q", field.Name)
	}
	return mongoDoc(bson.M{"$expr": bson.M{op: bson.A{expr, value}}}), nil
}

// mongoAccessors maps CEL timestamp accessors to date operators and the
// offset subtracted to match CEL's base. Dates are evaluated in UTC.
var mongoAccessors = map[string]struct {
	op  string
	off int64
}{
	"getFullYear":   {"$year", 0},
	"getMonth":      {"$month", 1},
	"getDate":       {"$dayOfMonth", 0},
	"getDayOfMonth": {"$dayOfMonth", 1},
	"getDayOfWeek":  {"$dayOfWeek", 1},
	"getDayOfYear":  {"$dayOfYear", 1},
	"getHours":      {"$hour", 0},
	"getMinutes":    {"$minute", 0},
	"getSeconds":    {"$second", 0},
}

func (r *mongoRenderer) renderAccessor(acc *FieldAccessorValue, op string, right ValueExpr) (mongoResult, error) {
	spec, ok := mongoAccessors[acc.Accessor]
	if !ok {
		return mongoResult{}, errors.Errorf("unsupported timestamp accessor %q", acc.Accessor)
	}
	path, err := r.scalarPath(acc.Field)
	if err != nil {
		return mongoResult{}, err
	}
	value, err := expectNumericLiteral(right)
	if err != nil {
		return mongoResult{}, err
	}
	var expr any = bson.M{spec.op: bson.M{"$toDate": bson.M{"$multiply": bson.A{"$" + path, int64(1000)}}}}
	if spec.off != 0 {
		expr = bson.M{"$subtract": bson.A{expr, spec.off}}
	}
	return mongoDoc(bson.M{"$expr": bson.M{op: bson.A{expr, value}}}), nil
}

// renderTagComprehension evaluates predicates against individual tags with
// exact, case-sensitive semantics.
func (r *mongoRenderer) renderTagComprehension(name string, pred PredicateExpr, kind ComprehensionKind) (mongoResult, error) {
	field, ok := r.schema.ResolveAlias(name)
	if !ok || field.Kind != FieldKindJSONList {
		return mongoResult{}, errors.Errorf("field %q is not a tag list", name)
	}
	if eq, ok := pred.(*EqualsPredicate); ok && kind == ComprehensionExists {
		return mongoDoc(bson.M{"tags": eq.Value}), nil
	}
	var cond any
	switch p := pred.(type) {
	case *EqualsPredicate:
		cond = bson.M{"$eq": bson.A{"$$t", p.Value}}
	case *StartsWithPredicate:
		cond = bson.M{"$regexMatch": bson.M{"input": "$$t", "regex": "^" + regexp.QuoteMeta(p.Prefix)}}
	case *EndsWithPredicate:
		cond = bson.M{"$regexMatch": bson.M{"input": "$$t", "regex": regexp.QuoteMeta(p.Suffix) + "$"}}
	case *ContainsPredicate:
		cond = bson.M{"$regexMatch": bson.M{"input": "$$t", "regex": regexp.QuoteMeta(p.Substring)}}
	default:
		return mongoResult{}, errors.Errorf("unsupported tag predicate %T", pred)
	}
	tags := bson.M{"$ifNull": bson.A{"$tags", bson.A{}}}
	matched := bson.M{"$size": bson.M{"$filter": bson.M{"input": tags, "as": "t", "cond": cond}}}
	switch kind {
	case ComprehensionExists:
		return mongoDoc(bson.M{"$expr": bson.M{"$gt": bson.A{matched, 0}}}), nil
	case ComprehensionExistsOne:
		return mongoDoc(bson.M{"$expr": bson.M{"$eq": bson.A{matched, 1}}}), nil
	case ComprehensionAll:
		return mongoDoc(bson.M{"$expr": bson.M{"$and": bson.A{
			bson.M{"$gt": bson.A{bson.M{"$size": tags}, 0}},
			bson.M{"$eq": bson.A{matched, bson.M{"$size": tags}}},
		}}}), nil
	default:
		return mongoResult{}, errors.Errorf("unsupported comprehension kind %s", kind)
	}
}
