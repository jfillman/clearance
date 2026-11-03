package decide

import (
	"errors"
	"fmt"
	"math/big"
	"path"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"github.com/jfillman/clearance/internal/pycompat"
	"github.com/jfillman/clearance/internal/scope"
)

// A bundle's context expressions (vars, arg_checks, app) run over the call itself: its tool, its arguments as sent,
// and the definition's profile as written. They are CEL like the rules, compiled once at load and type-checked, with
// a small library of total functions (none fails on a value of the wrong shape: it answers null, "", 0, -1 or
// false), so an expression written with type() guards decides on any input the way the Python reference did.
//
//	tool.name string, tool.known bool, tool.tier int, tool.writes_files bool, tool.reads_repo bool
//	args      map(string, dyn)   the call's arguments (an integer outside int64 is neither int nor double)
//	profile   dyn                the definition's profile, null when it has none
//	ctx.<var> the bundle's earlier vars
//
//	py.get(dyn, string) dyn               d.get(k) on a mapping, else null
//	py.strlist(dyn) list(string)          a list's string elements; a string's characters (list("abc")); else []
//	py.strip(string) string               str.strip()
//	py.len(string) int                    len(str): code points
//	py.utf8len(string) int                len(str.encode()): bytes
//	py.json_len(dyn) int                  len(json.dumps(v)), -1 when it does not encode
//	py.trim_prefix(string, list(string)) string   the string without the first prefix of the list it starts with
//	path.norm(dyn) string                 a safe repo-relative path normalised (posixpath.normpath), "" when it is not one
//	path.base(string) string              posixpath.basename
//	glob.match(string, string) bool       fnmatch.fnmatchcase
//	glob.any(string, list(string)) bool   fnmatchcase against any of the globs
//
// plus cel-go's strings extension (lastIndexOf, substring, ...).

// MaxContextCost bounds one context expression's evaluation. Context expressions read the arguments as sent (up to
// MaxRequestBytes), so their cost is not estimated at load, only cut off here (an expression over it denies, R000).
const MaxContextCost = 50_000_000

// The context expressions' variables.
const (
	cvToolName = iota
	cvToolKnown
	cvToolTier
	cvToolWritesFiles
	cvToolReadsRepo
	cvArgs
	cvProfile
	nCtx
)

var ctxVarNames = [nCtx]string{"tool.name", "tool.known", "tool.tier", "tool.writes_files", "tool.reads_repo", "args", "profile"}

var ctxVarTypes = [nCtx]*cel.Type{cel.StringType, cel.BoolType, cel.IntType, cel.BoolType, cel.BoolType,
	cel.MapType(cel.StringType, cel.DynType), cel.DynType}

// bigIntType is an integer outside int64, as the arguments carry it: neither int nor double in CEL, so a type()
// guard treats it as Python's `isinstance(v, int)` bounded checks do (out of range), and py.json_len still sees it.
var bigIntType = types.NewOpaqueType("py.bigint")

type bigInt struct{ v *big.Int }

func (b bigInt) ConvertToNative(reflect.Type) (any, error) {
	return nil, errors.New("py.bigint: no conversion")
}
func (b bigInt) ConvertToType(t ref.Type) ref.Val {
	if t == types.TypeType {
		return bigIntType
	}
	return types.NewErr("py.bigint: no conversion to %s", t.TypeName())
}
func (b bigInt) Equal(o ref.Val) ref.Val {
	ob, ok := o.(bigInt)
	return types.Bool(ok && ob.v.Cmp(b.v) == 0)
}
func (b bigInt) Type() ref.Type { return bigIntType }
func (b bigInt) Value() any     { return b.v }

// toCEL is a pycompat value (decoded JSON) as a CEL value.
func toCEL(v any) ref.Val {
	switch x := v.(type) {
	case nil:
		return types.NullValue
	case bool:
		return types.Bool(x)
	case int64:
		return types.Int(x)
	case *big.Int:
		return bigInt{x}
	case float64:
		return types.Double(x)
	case string:
		return types.String(x)
	case []any:
		out := make([]ref.Val, len(x))
		for i, e := range x {
			out[i] = toCEL(e)
		}
		return types.NewRefValList(types.DefaultTypeAdapter, out)
	case *pycompat.Map:
		out := make(map[ref.Val]ref.Val, x.Len())
		for i := range x.Len() {
			k, e := x.At(i)
			out[toCEL(k)] = toCEL(e)
		}
		return types.NewRefValMap(types.DefaultTypeAdapter, out)
	}
	return types.NullValue // not a JSON value (a YAML timestamp never reaches the arguments)
}

// fromCEL is a CEL value back as a pycompat value, for py.json_len. Map order is not kept (a length does not
// depend on it).
func fromCEL(v ref.Val) (any, bool) {
	switch x := v.(type) {
	case types.Null:
		return nil, true
	case types.Bool:
		return bool(x), true
	case types.Int:
		return int64(x), true
	case bigInt:
		return x.v, true
	case types.Double:
		return float64(x), true
	case types.String:
		return string(x), true
	case traits.Mapper:
		m := pycompat.NewMap(0)
		it := x.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			kv, ok := fromCEL(k)
			if !ok {
				return nil, false
			}
			ev, ok := fromCEL(x.Get(k))
			if !ok {
				return nil, false
			}
			m.Set(kv, ev)
		}
		return m, true
	case traits.Lister:
		var out []any
		it := x.Iterator()
		for it.HasNext() == types.True {
			ev, ok := fromCEL(it.Next())
			if !ok {
				return nil, false
			}
			out = append(out, ev)
		}
		if out == nil {
			out = []any{}
		}
		return out, true
	}
	return nil, false
}

func ctxEnv(globs *scope.Globs, extra []string, extraTypes []*cel.Type) (*cel.Env, error) {
	var opts []cel.EnvOption
	for i := range ctxVarNames {
		opts = append(opts, cel.Variable(ctxVarNames[i], ctxVarTypes[i]))
	}
	for i, n := range extra {
		opts = append(opts, cel.Variable(n, extraTypes[i]))
	}
	str := func(v ref.Val) (string, bool) { s, ok := v.(types.String); return string(s), ok }
	opts = append(opts, ext.Strings(),
		cel.Function("py.get", cel.Overload("py_get_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, cel.DynType,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val {
				mm, ok := m.(traits.Mapper)
				if !ok {
					return types.NullValue
				}
				if v, found := mm.Find(k); found {
					return v
				}
				return types.NullValue
			}))),
		cel.Function("py.strlist", cel.Overload("py_strlist_dyn", []*cel.Type{cel.DynType}, cel.ListType(cel.StringType),
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				var out []string
				switch x := v.(type) {
				case types.String:
					for _, r := range string(x) {
						out = append(out, string(r))
					}
				case traits.Lister:
					it := x.Iterator()
					for it.HasNext() == types.True {
						if s, ok := it.Next().(types.String); ok {
							out = append(out, string(s))
						}
					}
				}
				return types.NewStringList(types.DefaultTypeAdapter, out)
			}))),
		cel.Function("py.strip", cel.Overload("py_strip_string", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { s, _ := str(v); return types.String(pycompat.Strip(s)) }))),
		cel.Function("py.len", cel.Overload("py_len_string", []*cel.Type{cel.StringType}, cel.IntType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { s, _ := str(v); return types.Int(pycompat.Len(s)) }))),
		cel.Function("py.utf8len", cel.Overload("py_utf8len_string", []*cel.Type{cel.StringType}, cel.IntType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { s, _ := str(v); return types.Int(len(s)) }))),
		cel.Function("py.json_len", cel.Overload("py_json_len_dyn", []*cel.Type{cel.DynType}, cel.IntType,
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				pv, ok := fromCEL(v)
				if !ok {
					return types.Int(-1)
				}
				n, err := pycompat.DumpsLen(pv)
				if err != nil {
					return types.Int(-1)
				}
				return types.Int(n)
			}))),
		cel.Function("py.trim_prefix", cel.Overload("py_trim_prefix_string_list", []*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
			cel.StringType, cel.BinaryBinding(func(v, l ref.Val) ref.Val {
				s, _ := str(v)
				if ls, ok := l.(traits.Lister); ok {
					it := ls.Iterator()
					for it.HasNext() == types.True {
						if p, ok := it.Next().(types.String); ok && strings.HasPrefix(s, string(p)) {
							return types.String(s[len(p):])
						}
					}
				}
				return types.String(s)
			}))),
		cel.Function("path.norm", cel.Overload("path_norm_dyn", []*cel.Type{cel.DynType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				s, ok := str(v)
				if !ok {
					return types.String("")
				}
				n, err := scope.Normalize(s)
				if err != nil {
					return types.String("")
				}
				return types.String(n)
			}))),
		cel.Function("path.base", cel.Overload("path_base_string", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(func(v ref.Val) ref.Val { s, _ := str(v); return types.String(path.Base(s)) }))),
		cel.Function("glob.match", cel.Overload("glob_match_string_string", []*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType, cel.BinaryBinding(func(n, p ref.Val) ref.Val {
				ns, _ := str(n)
				ps, _ := str(p)
				return types.Bool(globs.FnmatchCase(ns, ps))
			}))),
		cel.Function("glob.any", cel.Overload("glob_any_string_list", []*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
			cel.BoolType, cel.BinaryBinding(func(n, l ref.Val) ref.Val {
				ns, _ := str(n)
				ls, ok := l.(traits.Lister)
				if !ok {
					return types.False
				}
				it := ls.Iterator()
				for it.HasNext() == types.True {
					if p, ok := it.Next().(types.String); ok && globs.FnmatchCase(ns, string(p)) {
						return types.True
					}
				}
				return types.False
			}))),
	)
	return cel.NewEnv(opts...)
}

// ctxProgram is one compiled context expression.
type ctxProgram struct {
	src  string
	want *cel.Type
	prg  cel.Program
}

func compileCtx(env *cel.Env, expr string, want *cel.Type, what string) (*ctxProgram, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("decide: %s does not compile: %w", what, iss.Err())
	}
	if !ast.OutputType().IsExactType(want) {
		return nil, fmt.Errorf("decide: %s: expression is %s, not %s", what, ast.OutputType(), want)
	}
	prg, err := env.Program(ast, cel.CostLimit(MaxContextCost), cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("decide: %s: %w", what, err)
	}
	return &ctxProgram{src: expr, want: want, prg: prg}, nil
}
