package resolver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-cli/cli/policyfile/rubyeval"
)

// includedLock is one include_policy's lock, reduced to what a compile reads
// from it (chef-cli's PolicyfileLocationSpecification#policyfile_lock).
type includedLock struct {
	name       string
	revisionID string
	// sourceOptions is what included_policy_locks records for the include.
	sourceOptions *jsonObject

	runList       []string
	namedRunLists map[string][]string
	defaultAttrs  *jsonObject
	overrideAttrs *jsonObject

	// demands is solution_dependencies.Policyfile, which joins the compile's
	// demands (chef-cli's cookbook_demands_from_policies).
	demands []demand
	// deps is solution_dependencies.dependencies: name -> version -> deps.
	deps map[string]map[string][]rubyeval.Dependency
	// cookbooks is cookbook_locks.
	cookbooks map[string]includedCookbook
}

type includedCookbook struct {
	version, dotted, identifier string
	sourceOptions               *jsonObject
}

// loadIncludes fetches the lock of every include_policy, in declaration
// order. rawIncludes is the evaluation's included_policies array, which keeps
// each declaration's source_options in the order the Policyfile wrote them.
func loadIncludes(ctx context.Context, eval *rubyeval.EvaluatedPolicy, rawIncludes []any, policyfileDir string, srvs *servers) ([]*includedLock, error) {
	locks := make([]*includedLock, 0, len(eval.IncludedPolicies))
	for i, inc := range eval.IncludedPolicies {
		opts := newJSONObject()
		if i < len(rawIncludes) {
			if entry, ok := rawIncludes[i].(*jsonObject); ok {
				if so, ok := entry.vals["source_options"].(*jsonObject); ok {
					opts = so
				}
			}
		}
		var (
			lock *includedLock
			err  error
		)
		switch {
		case opts.str("path") != "" && opts.str("git") == "":
			lock, err = loadPathInclude(inc.Name, opts, policyfileDir)
		case opts.str("server") != "":
			lock, err = loadServerInclude(ctx, inc.Name, opts, srvs)
		default:
			return nil, fmt.Errorf("cinc: include_policy %q needs a path: or server: source; git: and remote: includes aren't supported yet", inc.Name)
		}
		if err != nil {
			return nil, err
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

// loadPathInclude reads an included lock from disk, the way chef-cli's
// LocalLockFetcher does: a directory means <name>.lock.json inside it, a
// policy_revision_id must match (a 10-character prefix is enough), and each
// cookbook's path source is rewritten relative to the including Policyfile.
func loadPathInclude(name string, opts *jsonObject, policyfileDir string) (*includedLock, error) {
	root, err := filepath.Abs(policyfileDir)
	if err != nil {
		return nil, err
	}
	path := opts.str("path")
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if isDir(path) {
		path = filepath.Join(path, name+".lock.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cinc: include_policy %q: we couldn't read its lock: %w", name, err)
	}
	lock, err := parseIncludedLock(name, data)
	if err != nil {
		return nil, err
	}
	if want := opts.str("policy_revision_id"); want != "" && lock.revisionID != want && !strings.HasPrefix(lock.revisionID, want) {
		return nil, fmt.Errorf("cinc: include_policy %q expects revision %s, but %s is revision %s", name, want, path, lock.revisionID)
	}
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	for cbName, cb := range lock.cookbooks {
		if p := cb.sourceOptions.str("path"); p != "" {
			cb.sourceOptions = cb.sourceOptions.clone()
			cb.sourceOptions.set("path", filepath.ToSlash(filepath.Join(rel, p)))
			lock.cookbooks[cbName] = cb
		}
	}
	lock.sourceOptions = opts
	return lock, nil
}

// loadServerInclude fetches an included lock from a server, the way chef-cli's
// ChefServerLockFetcher does: policy_name defaults to the include's name, the
// lock is read at policy_revision_id or from policy_group, every cookbook is
// sourced from the server's cookbook artifacts by identifier, and the
// recorded source options gain the revision that was read.
func loadServerInclude(ctx context.Context, name string, opts *jsonObject, srvs *servers) (*includedLock, error) {
	url := opts.str("server")
	ref := PolicyRef{Name: opts.str("policy_name"), Group: opts.str("policy_group"), RevisionID: opts.str("policy_revision_id")}
	if ref.Name == "" {
		ref.Name = name
	}
	if ref.Group == "" && ref.RevisionID == "" {
		return nil, fmt.Errorf("cinc: include_policy %q names a server, so it also needs a policy_group: or a policy_revision_id:", name)
	}
	srv, err := srvs.get(url)
	if err != nil {
		return nil, err
	}
	data, err := srv.FetchPolicyLock(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("cinc: include_policy %q: we couldn't fetch its lock from %s: %w", name, url, err)
	}
	lock, err := parseIncludedLock(name, data)
	if err != nil {
		return nil, err
	}
	for cbName, cb := range lock.cookbooks {
		so := newJSONObject()
		so.set("chef_server_artifact", url)
		so.set("identifier", cb.identifier)
		cb.sourceOptions = so
		lock.cookbooks[cbName] = cb
	}
	lockOpts := opts.clone()
	if lockOpts.str("policy_name") == "" {
		lockOpts.set("policy_name", name)
	}
	lockOpts.set("policy_revision_id", lock.revisionID)
	lock.sourceOptions = lockOpts
	return lock, nil
}

// solutionKeyRE splits a solution_dependencies key, "name (version)".
var solutionKeyRE = regexp.MustCompile(`^(.+) \((.+)\)$`)

// parseIncludedLock reads the parts of a lock document an include uses.
func parseIncludedLock(name string, data []byte) (*includedLock, error) {
	bad := func(what string) error {
		return fmt.Errorf("cinc: include_policy %q: its lock has %s", name, what)
	}
	parsed, err := parseOrdered(data)
	if err != nil {
		return nil, fmt.Errorf("cinc: include_policy %q: its lock isn't valid JSON: %w", name, err)
	}
	doc, ok := parsed.(*jsonObject)
	if !ok {
		return nil, bad("no top-level object")
	}
	lock := &includedLock{
		name:          name,
		revisionID:    doc.str("revision_id"),
		namedRunLists: map[string][]string{},
		defaultAttrs:  doc.object("default_attributes"),
		overrideAttrs: doc.object("override_attributes"),
		deps:          map[string]map[string][]rubyeval.Dependency{},
		cookbooks:     map[string]includedCookbook{},
	}
	if lock.revisionID == "" {
		return nil, bad("no revision_id")
	}
	if lock.runList, ok = stringList(doc.vals["run_list"]); !ok {
		return nil, bad("a malformed run_list")
	}
	named := doc.object("named_run_lists")
	for _, k := range named.keys {
		if lock.namedRunLists[k], ok = stringList(named.vals[k]); !ok {
			return nil, bad(fmt.Sprintf("a malformed named run list %q", k))
		}
	}
	locks := doc.object("cookbook_locks")
	for _, cbName := range locks.keys {
		cl, ok := locks.vals[cbName].(*jsonObject)
		if !ok {
			return nil, bad(fmt.Sprintf("a malformed cookbook lock for %q", cbName))
		}
		lock.cookbooks[cbName] = includedCookbook{
			version:       cl.str("version"),
			dotted:        cl.str("dotted_decimal_identifier"),
			identifier:    cl.str("identifier"),
			sourceOptions: cl.object("source_options"),
		}
	}
	sol := doc.object("solution_dependencies")
	pf, _ := sol.vals["Policyfile"].([]any)
	for _, entry := range pf {
		pair, ok := stringList(entry)
		if !ok || len(pair) != 2 {
			return nil, bad("a malformed solution_dependencies Policyfile entry")
		}
		c, err := ParseConstraint(pair[1])
		if err != nil {
			return nil, bad(fmt.Sprintf("an invalid constraint %q for cookbook %q", pair[1], pair[0]))
		}
		lock.demands = append(lock.demands, demand{name: pair[0], constraint: c})
	}
	deps := sol.object("dependencies")
	for _, key := range deps.keys {
		m := solutionKeyRE.FindStringSubmatch(key)
		if m == nil {
			return nil, bad(fmt.Sprintf("a malformed solution_dependencies key %q", key))
		}
		list, _ := deps.vals[key].([]any)
		cbDeps := make([]rubyeval.Dependency, 0, len(list))
		for _, entry := range list {
			pair, ok := stringList(entry)
			if !ok || len(pair) != 2 {
				return nil, bad(fmt.Sprintf("a malformed dependency of %q", key))
			}
			cbDeps = append(cbDeps, rubyeval.Dependency{Name: pair[0], Constraint: pair[1]})
		}
		if lock.deps[m[1]] == nil {
			lock.deps[m[1]] = map[string][]rubyeval.Dependency{}
		}
		lock.deps[m[1]][m[2]] = cbDeps
	}
	return lock, nil
}

// includedSource is chef-cli's IncludedPoliciesCookbookSource: the cookbooks
// the included locks pin, each at exactly the version and from exactly the
// source its lock records. It is preferred over every default_source for the
// cookbooks it provides.
type includedSource struct {
	// versions is the source's universe: name -> version -> deps.
	versions map[string]map[string][]rubyeval.Dependency
	// options maps name -> version -> the source_options to fetch it from.
	options map[string]map[string]*jsonObject
}

// newIncludedSource merges the included locks, failing when two of them
// disagree about a cookbook the way chef-cli does.
func newIncludedSource(includes []*includedLock) (*includedSource, error) {
	src := &includedSource{versions: map[string]map[string][]rubyeval.Dependency{}, options: map[string]map[string]*jsonObject{}}
	for _, lock := range includes {
		for _, name := range sortedKeys(lock.deps) {
			for ver, deps := range lock.deps[name] {
				existing, ok := src.versions[name]
				prev, hasVer := existing[ver]
				switch {
				case !ok:
					src.versions[name] = map[string][]rubyeval.Dependency{ver: deps}
				case !hasVer:
					return nil, fmt.Errorf("cinc: included policies lock different versions of cookbook %q", name)
				case !slices.Equal(prev, deps):
					return nil, fmt.Errorf("cinc: included policies disagree on the dependencies of cookbook %q %s", name, ver)
				}
			}
		}
		for _, name := range sortedKeys(lock.cookbooks) {
			cb := lock.cookbooks[name]
			existing, ok := src.options[name]
			switch {
			case !ok:
				src.options[name] = map[string]*jsonObject{}
			case existing[cb.version] == nil:
				return nil, fmt.Errorf("cinc: included policies lock different versions of cookbook %q", name)
			case canonicalize(existing[cb.version]) != canonicalize(cb.sourceOptions):
				return nil, fmt.Errorf("cinc: included policies lock cookbook %q from different sources", name)
			}
			// A lock uploaded through the compatibility API can key
			// solution_dependencies by the dotted-decimal identifier while
			// cookbook_locks carries the metadata version, so register both.
			for _, v := range []string{cb.version, cb.dotted} {
				if v != "" {
					src.options[name][v] = cb.sourceOptions
				}
			}
		}
	}
	return src, nil
}

// candidates returns the source's versions of name, or nil when it has none.
func (s *includedSource) candidates(name string) []candidate {
	var out []candidate
	for ver, deps := range s.versions[name] {
		if v, err := ParseVersion(ver); err == nil {
			out = append(out, candidate{version: v, deps: deps})
		}
	}
	return out
}

// expandRunList is chef-cli's expanded_run_list: every included lock's run
// list, then the Policyfile's own, without repeating an item.
func expandRunList(includes []*includedLock, own []string) []string {
	lists := make([][]string, 0, len(includes)+1)
	for _, lock := range includes {
		lists = append(lists, lock.runList)
	}
	return appendRunListItems(nil, append(lists, own)...)
}

// expandNamedRunLists is chef-cli's expanded_named_run_lists.
func expandNamedRunLists(includes []*includedLock, own map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, lock := range includes {
		for name, items := range lock.namedRunLists {
			out[name] = appendRunListItems(out[name], items)
		}
	}
	for name, items := range own {
		out[name] = appendRunListItems(out[name], items)
	}
	return out
}

// appendRunListItems appends items the way Chef::RunList#<< does: an item
// already present (same type, name and version) is not added again.
func appendRunListItems(base []string, lists ...[]string) []string {
	seen := map[string]bool{}
	for _, item := range base {
		seen[runListItemKey(item)] = true
	}
	for _, items := range lists {
		for _, item := range items {
			if key := runListItemKey(item); !seen[key] {
				seen[key] = true
				base = append(base, item)
			}
		}
	}
	return base
}

// mergeIncludedAttributes is chef-cli's default_attributes and
// override_attributes: the Policyfile's own tree deep-merged with every
// included lock's, after checking that no two of them set one attribute to
// different values.
func mergeIncludedAttributes(own *jsonObject, includes []*includedLock, attrs func(*includedLock) *jsonObject) (*jsonObject, error) {
	leaves := map[string]attributeLeaf{}
	if err := checkAttributes(leaves, "user-specified", "", own); err != nil {
		return nil, err
	}
	merged := own
	for _, lock := range includes {
		if err := checkAttributes(leaves, lock.name, "", attrs(lock)); err != nil {
			return nil, err
		}
		merged = deepMerge(attrs(lock), merged).(*jsonObject)
	}
	return merged, nil
}

type attributeLeaf struct {
	source, value string
}

// checkAttributes is chef-cli's AttributeMergeChecker: two sources may set the
// same attribute only to the same value.
func checkAttributes(leaves map[string]attributeLeaf, source, path string, obj *jsonObject) error {
	for _, k := range obj.keys {
		p := path + "[" + k + "]"
		if child, ok := obj.vals[k].(*jsonObject); ok {
			if leaf, ok := leaves[p]; ok {
				return attributeConflict(p, leaf.source, source)
			}
			if err := checkAttributes(leaves, source, p, child); err != nil {
				return err
			}
			continue
		}
		value := canonicalize(obj.vals[k])
		if leaf, ok := leaves[p]; ok {
			if leaf.value != value {
				return attributeConflict(p, leaf.source, source)
			}
			continue
		}
		for other := range leaves {
			if strings.HasPrefix(other, p+"[") {
				return attributeConflict(p, leaves[other].source, source)
			}
		}
		leaves[p] = attributeLeaf{source: source, value: value}
	}
	return nil
}

func attributeConflict(path, a, b string) error {
	return fmt.Errorf("cinc: attribute '%s' is set to different values by %s and %s", path, a, b)
}

// deepMerge is Chef::Mixin::DeepMerge.deep_merge(src, dst): src's keys merge
// into a copy of dst, objects recursively, arrays as a union.
func deepMerge(src, dst any) any {
	switch s := src.(type) {
	case *jsonObject:
		d, ok := dst.(*jsonObject)
		if !ok {
			return s
		}
		out := d.clone()
		for _, k := range s.keys {
			if dv, ok := out.vals[k]; ok {
				out.vals[k] = deepMerge(s.vals[k], dv)
			} else {
				out.set(k, s.vals[k])
			}
		}
		return out
	case []any:
		d, ok := dst.([]any)
		if !ok {
			return s
		}
		var out []any
		seen := map[string]bool{}
		for _, e := range append(slices.Clone(d), s...) {
			if key := canonicalize(e); !seen[key] {
				seen[key] = true
				out = append(out, e)
			}
		}
		return out
	default:
		return src
	}
}

// stringList reads a JSON array of strings.
func stringList(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		if out[i], ok = e.(string); !ok {
			return nil, false
		}
	}
	return out, true
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
