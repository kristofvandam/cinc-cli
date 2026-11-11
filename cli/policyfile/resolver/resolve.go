// Package resolver completes a Policyfile install: it takes the evaluated
// intent of a Policyfile.rb (from cli/policyfile/rubyeval) and produces a fully
// resolved, push-ready Policyfile.lock.json that is byte-for-byte compatible
// with what `chef install` writes.
//
// It is the dependency-resolution half the evaluation engine deliberately left
// out, and it reproduces chef exactly in three places that must interoperate
// with a Chef Infra Server:
//
//   - Cookbook identifiers (identifier.go, computed by cinc-api): the SHA1
//     content identifier and its dotted-decimal reinterpretation, matching
//     CookbookProfiler::Identifiers.
//   - Version/dependency solving (solver.go): a deterministic backtracking
//     solver over cookbook metadata `depends` and the Policyfile's per-cookbook
//     constraints, selecting the same versions chef's Molinillo-based solver
//     does.
//   - Lock serialization (yajl.go): FFI_Yajl pretty output and the canonical
//     revision-string SHA256 that becomes the revision_id.
//
// Cookbooks resolve from path: sources (metadata read from metadata.json or
// evaluated from metadata.rb with the embedded Ruby engine) and from a
// `default_source :chef_server` (through a ChefServer). include_policy reads
// path: and server: locks. Git, Supermarket and other sources are not yet
// resolved here.
package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cinc-project/cinc-cli/cli/policyfile/rubyeval"
)

// Result is a fully resolved Policyfile lock plus a summary of what was
// resolved, for the command's human output.
type Result struct {
	// LockJSON is the Policyfile.lock.json, encoded byte-identically to chef.
	LockJSON []byte
	// RevisionID is the lock's revision_id (SHA256 of the canonical revision
	// string).
	RevisionID string
	// Cookbooks summarizes each resolved cookbook, sorted by name.
	Cookbooks []CookbookSummary
}

// CookbookSummary describes one resolved cookbook for display.
type CookbookSummary struct {
	Name       string
	Version    string
	Identifier string
	// Source is the path a local cookbook was read from, or the server a
	// fetched one came from.
	Source string
	// Dir is the cookbook's root on disk, the files a push uploads.
	Dir string
}

// Options is everything Resolve needs beyond the evaluated Policyfile.
type Options struct {
	// Engine evaluates cookbook metadata.rb files. Nil means a new engine.
	Engine *rubyeval.Engine
	// RawEval is the engine's canonical JSON output for the Policyfile. It
	// preserves chef's exact attribute and include source_options key order.
	// Without it the EvaluatedPolicy's maps are used, keys sorted.
	RawEval []byte
	// PolicyfileDir is the directory relative path: cookbook sources and
	// include_policy path: locks resolve against.
	PolicyfileDir string
	// Server returns the server behind a URL: the URI of
	// `default_source :chef_server, URI` or the server: of an include_policy.
	// Nil means a Policyfile that names a server can't be resolved.
	Server func(url string) (ChefServer, error)
	// IncludedCookbooksOnly limits what an include_policy contributes to its
	// cookbooks: the versions its lock pins, from the sources it records. Its
	// run lists and attributes are not merged into the lock. chef-cli always
	// merges them, so this is not chef behaviour; it is for callers that
	// manage the run list and attributes of every policy themselves.
	IncludedCookbooksOnly bool
}

// Resolve turns an evaluated Policyfile into a push-ready lock.
func Resolve(ctx context.Context, eval *rubyeval.EvaluatedPolicy, opts Options) (*Result, error) {
	eng := opts.Engine
	if eng == nil {
		eng = rubyeval.NewEngine()
	}
	root, err := evaluationObject(eval, opts.RawEval)
	if err != nil {
		return nil, err
	}
	srvs := &servers{open: opts.Server}

	rawIncludes, _ := root.vals["included_policies"].([]any)
	includes, err := loadIncludes(ctx, eval, rawIncludes, opts.PolicyfileDir, srvs)
	if err != nil {
		return nil, err
	}
	incSrc, err := newIncludedSource(includes)
	if err != nil {
		return nil, err
	}

	// What the includes merge into the lock beyond their cookbooks.
	merged := includes
	if opts.IncludedCookbooksOnly {
		merged = nil
	}
	runList := expandRunList(merged, eval.RunList)
	namedRunLists := expandNamedRunLists(merged, eval.NamedRunLists)
	defAttrs, err := mergeIncludedAttributes(root.object("default_attributes"), merged, func(l *includedLock) *jsonObject { return l.defaultAttrs })
	if err != nil {
		return nil, err
	}
	ovrAttrs, err := mergeIncludedAttributes(root.object("override_attributes"), merged, func(l *includedLock) *jsonObject { return l.overrideAttrs })
	if err != nil {
		return nil, err
	}

	// A declared cookbook with a path: source is one version on disk; one
	// without a source only constrains the version a default source supplies.
	cookbooks := map[string]*cookbookInfo{}
	for _, name := range sortedCookbookNames(eval.Cookbooks) {
		spec := eval.Cookbooks[name]
		path, ok := spec.SourceOptions["path"].(string)
		if !ok {
			if !constraintOnly(spec.SourceOptions) {
				return nil, unsupportedSourceErr(name, spec.SourceOptions)
			}
			continue
		}
		info, err := loadPathCookbook(ctx, eng, opts.PolicyfileDir, name, path)
		if err != nil {
			return nil, err
		}
		cookbooks[name] = info
	}

	// The solver's universe is chef's artifacts_graph: the default source,
	// overridden by the included locks for the cookbooks they pin, overridden
	// by the declared path: cookbooks.
	chefURL := defaultChefServer(eval)
	u := universe{}
	if chefURL != "" {
		srv, err := srvs.get(chefURL)
		if err != nil {
			return nil, err
		}
		su, err := srv.Universe(ctx)
		if err != nil {
			return nil, fmt.Errorf("cinc: we couldn't read the cookbook universe from %s: %w", chefURL, err)
		}
		u = serverUniverse(su)
	}
	for name := range incSrc.versions {
		u[name] = incSrc.candidates(name)
	}
	for name, info := range cookbooks {
		u[name] = []candidate{{version: info.version, deps: info.deps}}
	}

	demands, err := buildDemands(eval, append(runList, flattenRunLists(namedRunLists)...), cookbooks, includes)
	if err != nil {
		return nil, err
	}
	solution, err := solve(u, demands)
	if err != nil {
		var nse *NoSolutionError
		if errors.As(err, &nse) && u[nse.Cookbook] == nil {
			return nil, noSourceErr(nse.Cookbook)
		}
		return nil, err
	}

	located, err := locateAll(ctx, sortedVersionKeys(solution), func(ctx context.Context, name string) (*cookbookInfo, error) {
		if info, ok := cookbooks[name]; ok {
			return info, nil
		}
		v := solution[name]
		if byVersion, ok := incSrc.options[name]; ok {
			so := byVersion[v.lockString()]
			if so == nil {
				return nil, fmt.Errorf("cinc: the included policies don't say where cookbook %q %s comes from", name, v.lockString())
			}
			return locateIncluded(ctx, eng, srvs, opts.PolicyfileDir, name, v, incSrc.versions[name][v.lockString()], so)
		}
		if chefURL == "" {
			return nil, noSourceErr(name)
		}
		srv, err := srvs.get(chefURL)
		if err != nil {
			return nil, err
		}
		return chefServerCookbook(ctx, srv, chefURL, name, v, candidateDeps(u[name], v))
	})
	if err != nil {
		return nil, err
	}

	lock, summaries, err := buildLock(eval, runList, namedRunLists, includes, defAttrs, ovrAttrs, located)
	if err != nil {
		return nil, err
	}

	revision := revisionID(lock)
	// revision_id must be the first key; rebuild with it leading.
	ordered := newJSONObject()
	ordered.set("revision_id", revision)
	for _, k := range lock.keys {
		ordered.set(k, lock.vals[k])
	}

	return &Result{
		LockJSON:   yajlEncode(ordered),
		RevisionID: revision,
		Cookbooks:  summaries,
	}, nil
}

// evaluationObject is the evaluation in the order-preserving value model:
// RawEval when there is one, else the EvaluatedPolicy itself.
func evaluationObject(eval *rubyeval.EvaluatedPolicy, rawEval []byte) (*jsonObject, error) {
	if rawEval == nil {
		var err error
		if rawEval, err = json.Marshal(eval); err != nil {
			return nil, err
		}
	}
	parsed, err := parseOrdered(rawEval)
	if err != nil {
		return nil, fmt.Errorf("cinc: parse evaluation output: %w", err)
	}
	if root, ok := parsed.(*jsonObject); ok {
		return root, nil
	}
	return newJSONObject(), nil
}

// constraintOnly reports whether a declared cookbook's source options leave
// it to the default source: none at all, or a chef_server: one, which chef
// also resolves through its default sources.
func constraintOnly(opts map[string]any) bool {
	for k := range opts {
		if k != "chef_server" {
			return false
		}
	}
	return true
}

// defaultChefServer returns the URI of the Policyfile's chef_server
// default_source, or "" when it declares none. Other default sources are not
// resolved yet; a cookbook only they could provide fails with noSourceErr.
func defaultChefServer(eval *rubyeval.EvaluatedPolicy) string {
	for _, s := range eval.DefaultSources {
		if s.Type == "chef_server" {
			return s.URI
		}
	}
	return ""
}

func flattenRunLists(named map[string][]string) []string {
	var out []string
	for _, name := range sortedKeys(named) {
		out = append(out, named[name]...)
	}
	return out
}

// buildDemands computes chef's graph_demands: a constraint for every cookbook
// in the run lists plus every declared cookbook, then every included lock's
// Policyfile demands. A fixed-version (path) source demands its exact version;
// an otherwise-declared cookbook demands its Policyfile constraint; anything
// else demands ">= 0.0.0".
func buildDemands(eval *rubyeval.EvaluatedPolicy, runLists []string, cookbooks map[string]*cookbookInfo, includes []*includedLock) ([]demand, error) {
	names := demandCookbookNames(eval, runLists)
	demands := make([]demand, 0, len(names))
	for _, name := range names {
		raw := ">= 0.0.0"
		if info, ok := cookbooks[name]; ok && info.fixed {
			raw = "= " + info.verStr
		} else if spec, ok := eval.Cookbooks[name]; ok && spec.VersionConstraint != "" {
			raw = spec.VersionConstraint
		}
		c, err := ParseConstraint(raw)
		if err != nil {
			return nil, fmt.Errorf("cinc: cookbook %q has invalid constraint %q: %w", name, raw, err)
		}
		demands = append(demands, demand{name: name, constraint: c})
	}
	for _, lock := range includes {
		demands = append(demands, lock.demands...)
	}
	return demands, nil
}

// demandCookbookNames is chef's cookbooks_for_demands: the union of cookbook
// names referenced by the run lists and cookbook names declared in the
// Policyfile, sorted for determinism.
func demandCookbookNames(eval *rubyeval.EvaluatedPolicy, runLists []string) []string {
	set := map[string]struct{}{}
	for _, item := range runLists {
		if cb := runListCookbookName(item); cb != "" {
			set[cb] = struct{}{}
		}
	}
	for name := range eval.Cookbooks {
		set[name] = struct{}{}
	}
	return sortedKeys(set)
}

// locateLimit bounds how many cookbooks are located at once: each one a
// server may have to send over the network.
const locateLimit = 4

// locateAll runs locate for every name, a few at a time, and returns the
// results by name. The first failure, in name order, is the one reported.
func locateAll(ctx context.Context, names []string, locate func(context.Context, string) (*cookbookInfo, error)) (map[string]*cookbookInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	infos := make([]*cookbookInfo, len(names))
	errs := make([]error, len(names))
	sem := make(chan struct{}, locateLimit)
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			if infos[i], errs[i] = locate(ctx, name); errs[i] != nil {
				cancel()
			}
		})
	}
	wg.Wait()
	out := make(map[string]*cookbookInfo, len(names))
	for i, name := range names {
		if errs[i] != nil && !errors.Is(errs[i], context.Canceled) {
			return nil, errs[i]
		}
		out[name] = infos[i]
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// locateIncluded fetches a cookbook an included lock pins from the source
// that lock records (chef-cli's create_spec_for_cookbook over the included
// policies' source). deps are the dependencies the included lock recorded.
func locateIncluded(ctx context.Context, eng *rubyeval.Engine, srvs *servers, policyfileDir, name string, v Version, deps []rubyeval.Dependency, so *jsonObject) (*cookbookInfo, error) {
	switch {
	case so.str("chef_server_artifact") != "":
		url := so.str("chef_server_artifact")
		srv, err := srvs.get(url)
		if err != nil {
			return nil, err
		}
		return chefServerArtifact(ctx, srv, url, name, so.str("identifier"), v, deps)
	case so.str("chef_server") != "":
		url := so.str("chef_server")
		srv, err := srvs.get(url)
		if err != nil {
			return nil, err
		}
		return chefServerCookbook(ctx, srv, url, name, v, deps)
	case so.str("path") != "":
		info, err := loadPathCookbook(ctx, eng, policyfileDir, name, so.str("path"))
		if err != nil {
			return nil, err
		}
		info.deps, info.fixed = deps, false
		return info, nil
	}
	return nil, fmt.Errorf("cinc: an included policy locks cookbook %q from a source we can't fetch yet; only path:, chef_server and chef_server_artifact sources are supported", name)
}

// candidateDeps returns the dependencies of version v among cands.
func candidateDeps(cands []candidate, v Version) []rubyeval.Dependency {
	for _, c := range cands {
		if c.version.Compare(v) == 0 {
			return c.deps
		}
	}
	return nil
}

// buildLock assembles every top-level lock field except revision_id (which is
// derived from the rest) in chef's key order, and returns a per-cookbook
// summary for display.
func buildLock(eval *rubyeval.EvaluatedPolicy, runList []string, namedRunLists map[string][]string, includes []*includedLock, defAttrs, ovrAttrs *jsonObject, cookbooks map[string]*cookbookInfo) (*jsonObject, []CookbookSummary, error) {
	lock := newJSONObject()
	lock.set("name", eval.Name)
	lock.set("run_list", normalizeRunList(runList))

	if len(namedRunLists) > 0 {
		named := newJSONObject()
		for _, name := range sortedStringKeys(namedRunLists) {
			named.set(name, normalizeRunList(namedRunLists[name]))
		}
		lock.set("named_run_lists", named)
	}

	included := make([]any, 0, len(includes))
	for _, inc := range includes {
		entry := newJSONObject()
		entry.set("name", inc.name)
		entry.set("revision_id", inc.revisionID)
		entry.set("source_options", inc.sourceOptions)
		included = append(included, entry)
	}
	lock.set("included_policy_locks", included)

	// cookbook_locks, sorted by name.
	locks := newJSONObject()
	names := sortedKeys(cookbooks)
	summaries := make([]CookbookSummary, 0, len(names))
	for _, name := range names {
		info := cookbooks[name]
		id, err := ComputeIdentifier(info.dir, info.verStr)
		if err != nil {
			return nil, nil, fmt.Errorf("cinc: cookbook %q: %w", name, err)
		}
		entry := newJSONObject()
		entry.set("version", info.verStr)
		entry.set("identifier", id.Content)
		entry.set("dotted_decimal_identifier", id.DottedDecimal)
		source := info.source
		if info.cached {
			entry.set("cache_key", info.cacheKey)
			entry.set("origin", info.origin)
			source = info.origin
		} else {
			entry.set("source", info.source)
			entry.set("cache_key", nil)
			entry.set("scm_info", nil)
		}
		entry.set("source_options", info.sourceOptions)
		locks.set(name, entry)
		summaries = append(summaries, CookbookSummary{
			Name: name, Version: info.verStr, Identifier: id.Content, Source: source, Dir: info.dir,
		})
	}
	lock.set("cookbook_locks", locks)
	lock.set("default_attributes", defAttrs)
	lock.set("override_attributes", ovrAttrs)
	lock.set("solution_dependencies", solutionDependencies(eval, cookbooks))
	return lock, summaries, nil
}

// solutionDependencies builds chef's solution_dependencies: the Policyfile
// demands and the per-version dependency lists, both in chef's exact shape and
// ordering. The Policyfile half is chef's all_cookbook_location_specs: a
// declared path: cookbook keeps its declared constraint, and every cookbook a
// source supplied is pinned "= version", the spec chef creates to fetch it.
func solutionDependencies(eval *rubyeval.EvaluatedPolicy, cookbooks map[string]*cookbookInfo) *jsonObject {
	out := newJSONObject()

	names := sortedKeys(cookbooks)
	pfArr := make([]any, 0, len(names))
	for _, name := range names {
		info := cookbooks[name]
		constraint := "= " + info.verStr
		if spec, ok := eval.Cookbooks[name]; ok && info.fixed {
			constraint = spec.VersionConstraint
		}
		pfArr = append(pfArr, []any{name, constraint})
	}
	out.set("Policyfile", pfArr)

	// "dependencies": {"name (version)": [[dep, constraint], ...]} sorted by key.
	deps := newJSONObject()
	for _, name := range names {
		info := cookbooks[name]
		key := fmt.Sprintf("%s (%s)", name, info.verStr)
		depArr := make([]any, 0, len(info.deps))
		for _, d := range info.deps {
			depArr = append(depArr, []any{d.Name, d.Constraint})
		}
		deps.set(key, depArr)
	}
	// Sort dependency keys lexically (chef does .sort.to_h).
	sortJSONObjectKeys(deps)
	out.set("dependencies", deps)
	return out
}

// revisionID computes the lock's revision_id: the SHA256 of chef's canonical
// revision string (name, run-list items, named run lists, cookbook id lines,
// and canonicalized attribute trees).
func revisionID(lock *jsonObject) string {
	var b strings.Builder
	b.WriteString("name:" + lock.str("name") + "\n")
	runList, _ := stringList(lock.vals["run_list"])
	for _, item := range runList {
		b.WriteString("run-list-item:" + item + "\n")
	}
	named := lock.object("named_run_lists")
	for _, name := range named.keys {
		items, _ := stringList(named.vals[name])
		for _, item := range items {
			b.WriteString("named-run-list:" + name + ";run-list-item:" + item + "\n")
		}
	}
	locks := lock.object("cookbook_locks")
	for _, name := range locks.keys {
		b.WriteString("cookbook:" + name + ";id:" + locks.object(name).str("identifier") + "\n")
	}
	b.WriteString("default_attributes:" + canonicalize(lock.vals["default_attributes"]) + "\n")
	b.WriteString("override_attributes:" + canonicalize(lock.vals["override_attributes"]) + "\n")
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// unsupportedSourceErr reports an honest error for a cookbook whose source the
// resolver does not yet handle.
func unsupportedSourceErr(name string, opts map[string]any) error {
	for _, k := range []string{"git", "github", "supermarket", "artifactserver"} {
		if _, ok := opts[k]; ok {
			return fmt.Errorf("cinc: cookbook %q uses a %s source, which the resolver can't resolve yet; only path: sources and a default_source :chef_server are supported", name, k)
		}
	}
	return fmt.Errorf("cinc: cookbook %q has no resolvable source (only path: sources and a default_source :chef_server are supported yet)", name)
}

// noSourceErr reports a required cookbook that none of the Policyfile's
// sources the resolver supports can provide.
func noSourceErr(name string) error {
	return fmt.Errorf("cinc: cookbook %q is required, but none of your sources provide it. Today we resolve path: cookbooks, a default_source :chef_server and included policies; Supermarket and git sources aren't supported yet", name)
}
