package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	cinc "github.com/cinc-project/cinc-api"

	"github.com/cinc-project/cinc-cli/cli/policyfile/rubyeval"
)

const testServerURL = "https://cinc.example.com/organizations/acme"

// fakeServer is an in-memory ChefServer: a universe, cookbook and artifact
// directories written on demand, and policy locks by name.
type fakeServer struct {
	t        *testing.T
	universe cinc.Universe
	locks    map[string][]byte // "name@group" or "name#revision"

	mu        sync.Mutex
	fetched   []string
	artifacts []string
}

func (s *fakeServer) Universe(context.Context) (cinc.Universe, error) { return s.universe, nil }

func (s *fakeServer) FetchCookbook(_ context.Context, name, version string) (string, error) {
	s.mu.Lock()
	s.fetched = append(s.fetched, name+"-"+version)
	s.mu.Unlock()
	if _, ok := s.universe[name][version]; !ok {
		return "", fmt.Errorf("no cookbook %s %s", name, version)
	}
	return writeTestCookbook(s.t, name, version, s.universe[name][version].Dependencies), nil
}

func (s *fakeServer) FetchCookbookArtifact(_ context.Context, name, identifier string) (string, error) {
	s.mu.Lock()
	s.artifacts = append(s.artifacts, name+"-"+identifier)
	s.mu.Unlock()
	version, ok := strings.CutPrefix(identifier, "id-")
	if !ok {
		return "", fmt.Errorf("no artifact %s %s", name, identifier)
	}
	return writeTestCookbook(s.t, name, version, nil), nil
}

func (s *fakeServer) FetchPolicyLock(_ context.Context, ref PolicyRef) ([]byte, error) {
	key := ref.Name + "@" + ref.Group
	if ref.RevisionID != "" {
		key = ref.Name + "#" + ref.RevisionID
	}
	if lock, ok := s.locks[key]; ok {
		return lock, nil
	}
	return nil, fmt.Errorf("no policy lock %s", key)
}

func (s *fakeServer) open(url string) (ChefServer, error) {
	if url != testServerURL {
		return nil, fmt.Errorf("unexpected server %s", url)
	}
	return s, nil
}

// writeTestCookbook writes a cookbook with a metadata.json and one recipe.
func writeTestCookbook(t *testing.T, name, version string, deps map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(dir, "recipes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if deps == nil {
		deps = map[string]string{}
	}
	md, _ := json.Marshal(map[string]any{"name": name, "version": version, "dependencies": deps})
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), md, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recipes", "default.rb"), []byte("log '"+name+"'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testUniverse() cinc.Universe {
	return cinc.Universe{
		"util": {"1.0.0": {}, "1.1.0": {}, "2.0.0": {}},
		"base": {"2.1.0": {Dependencies: map[string]string{"util": "~> 1.0"}}},
		"app":  {"0.3.0": {Dependencies: map[string]string{"util": ">= 0", "base": ">= 0.0.0"}}},
	}
}

// testLock is the subset of a lock document the tests read back.
type testLock struct {
	Name                string   `json:"name"`
	RunList             []string `json:"run_list"`
	IncludedPolicyLocks []struct {
		Name          string         `json:"name"`
		RevisionID    string         `json:"revision_id"`
		SourceOptions map[string]any `json:"source_options"`
	} `json:"included_policy_locks"`
	CookbookLocks map[string]struct {
		Version       string         `json:"version"`
		CacheKey      string         `json:"cache_key"`
		Origin        string         `json:"origin"`
		SourceOptions map[string]any `json:"source_options"`
	} `json:"cookbook_locks"`
	DefaultAttributes    map[string]any `json:"default_attributes"`
	SolutionDependencies struct {
		Policyfile   [][]string            `json:"Policyfile"`
		Dependencies map[string][][]string `json:"dependencies"`
	} `json:"solution_dependencies"`
}

func resolveTest(t *testing.T, srv *fakeServer, eval *rubyeval.EvaluatedPolicy, opts Options) (*Result, testLock) {
	t.Helper()
	opts.Server = srv.open
	res, err := Resolve(context.Background(), eval, opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var lock testLock
	if err := json.Unmarshal(res.LockJSON, &lock); err != nil {
		t.Fatalf("lock JSON: %v\n%s", err, res.LockJSON)
	}
	return res, lock
}

// TestResolveChefServerDefaultSource resolves a policy against a
// default_source :chef_server and checks the lock takes the shape chef-cli
// writes for it (verified byte for byte against chef-cli 5.6.14 and
// cinc-server-ng): every cookbook a cached chef_server lock pinned "= version"
// in the Policyfile demands, with dependencies sorted and normalized.
func TestResolveChefServerDefaultSource(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse()}
	eval := &rubyeval.EvaluatedPolicy{
		Name:           "app",
		RunList:        []string{"app"},
		DefaultSources: []rubyeval.DefaultSource{{Type: "chef_server", URI: testServerURL}},
	}
	res, lock := resolveTest(t, srv, eval, Options{})

	if !slices.Equal(lock.RunList, []string{"recipe[app::default]"}) {
		t.Errorf("run_list = %v", lock.RunList)
	}
	want := map[string]string{"app": "0.3.0", "base": "2.1.0", "util": "1.1.0"}
	for name, version := range want {
		cl := lock.CookbookLocks[name]
		if cl.Version != version || cl.CacheKey != name+"-"+version || cl.Origin != testServerURL {
			t.Errorf("cookbook_locks[%s] = %+v, want version %s cached from the server", name, cl, version)
		}
		if cl.SourceOptions["chef_server"] != testServerURL || cl.SourceOptions["version"] != version {
			t.Errorf("cookbook_locks[%s].source_options = %v", name, cl.SourceOptions)
		}
	}
	if got := lock.SolutionDependencies.Policyfile; !slices.EqualFunc(got, [][]string{{"app", "= 0.3.0"}, {"base", "= 2.1.0"}, {"util", "= 1.1.0"}}, slices.Equal) {
		t.Errorf("Policyfile demands = %v", got)
	}
	if got := lock.SolutionDependencies.Dependencies["app (0.3.0)"]; !slices.EqualFunc(got, [][]string{{"base", ">= 0.0.0"}, {"util", ">= 0.0.0"}}, slices.Equal) {
		t.Errorf("app dependencies = %v, want sorted and normalized", got)
	}
	// The entry keys follow chef-cli's CachedCookbook#lock_data order.
	entry := `"cache_key": "util-1.1.0",
      "origin": "` + testServerURL + `",
      "source_options": {
        "chef_server": "` + testServerURL + `",
        "version": "1.1.0"
      }`
	if !strings.Contains(string(res.LockJSON), entry) {
		t.Errorf("util lock entry not in chef-cli's shape:\n%s", res.LockJSON)
	}
	for _, cb := range res.Cookbooks {
		if cb.Dir == "" || cb.Source != testServerURL {
			t.Errorf("summary %+v, want the fetched directory and the server as source", cb)
		}
	}
	if len(srv.fetched) != 3 {
		t.Errorf("fetched %v, want the three solved cookbooks", srv.fetched)
	}
}

// TestResolveDeclaredConstraintWithChefServer pins a cookbook the way a
// `cookbook 'util', '= 1.0.0'` line does: the default source supplies it at
// that version, and the lock pins what it supplied.
func TestResolveDeclaredConstraintWithChefServer(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse()}
	eval := &rubyeval.EvaluatedPolicy{
		Name:           "base",
		RunList:        []string{"recipe[base::default]"},
		DefaultSources: []rubyeval.DefaultSource{{Type: "chef_server", URI: testServerURL}},
		Cookbooks:      map[string]rubyeval.CookbookSpec{"util": {VersionConstraint: "= 1.0.0"}},
	}
	_, lock := resolveTest(t, srv, eval, Options{})
	if v := lock.CookbookLocks["util"].Version; v != "1.0.0" {
		t.Errorf("util = %s, want the declared 1.0.0", v)
	}
	if got := lock.SolutionDependencies.Policyfile; !slices.EqualFunc(got, [][]string{{"base", "= 2.1.0"}, {"util", "= 1.0.0"}}, slices.Equal) {
		t.Errorf("Policyfile demands = %v", got)
	}
}

// includedBaseLock is a lock for policy "base" as a server stores it.
const includedBaseLock = `{
  "revision_id": "base-rev-1",
  "name": "base",
  "run_list": ["recipe[base::default]"],
  "included_policy_locks": [],
  "cookbook_locks": {
    "base": {"version": "2.1.0", "identifier": "id-2.1.0", "dotted_decimal_identifier": "1.2.3", "cache_key": "base-2.1.0", "origin": "` + testServerURL + `", "source_options": {"chef_server": "` + testServerURL + `", "version": "2.1.0"}},
    "util": {"version": "1.0.0", "identifier": "id-1.0.0", "dotted_decimal_identifier": "4.5.6", "cache_key": "util-1.0.0", "origin": "` + testServerURL + `", "source_options": {"chef_server": "` + testServerURL + `", "version": "1.0.0"}}
  },
  "default_attributes": {"base": {"tz": "UTC"}, "shared": "same"},
  "override_attributes": {},
  "solution_dependencies": {
    "Policyfile": [["base", "= 2.1.0"], ["util", "= 1.0.0"]],
    "dependencies": {"base (2.1.0)": [["util", "~> 1.0"]], "util (1.0.0)": []}
  }
}`

func includeEval() *rubyeval.EvaluatedPolicy {
	return &rubyeval.EvaluatedPolicy{
		Name:              "app",
		RunList:           []string{"app::default"},
		DefaultSources:    []rubyeval.DefaultSource{{Type: "chef_server", URI: testServerURL}},
		IncludedPolicies:  []rubyeval.IncludedPolicy{{Name: "base", SourceOptions: map[string]any{"server": testServerURL, "policy_group": "prod"}}},
		DefaultAttributes: map[string]any{"app": map[string]any{"port": 8080}, "shared": "same"},
	}
}

// TestResolveServerInclude includes a policy from a server group the way
// chef-cli's ChefServerLockFetcher does: its cookbooks come from the server's
// cookbook artifacts at the identifiers it locked, its run list and
// attributes merge into the lock, and included_policy_locks records the
// revision that was read.
func TestResolveServerInclude(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse(), locks: map[string][]byte{"base@prod": []byte(includedBaseLock)}}
	_, lock := resolveTest(t, srv, includeEval(), Options{})

	if !slices.Equal(lock.RunList, []string{"recipe[base::default]", "recipe[app::default]"}) {
		t.Errorf("run_list = %v, want the included run list first", lock.RunList)
	}
	if lock.DefaultAttributes["base"] == nil || lock.DefaultAttributes["app"] == nil {
		t.Errorf("default_attributes = %v, want both trees merged", lock.DefaultAttributes)
	}
	if len(lock.IncludedPolicyLocks) != 1 || lock.IncludedPolicyLocks[0].RevisionID != "base-rev-1" {
		t.Fatalf("included_policy_locks = %+v", lock.IncludedPolicyLocks)
	}
	so := lock.IncludedPolicyLocks[0].SourceOptions
	if so["policy_name"] != "base" || so["policy_revision_id"] != "base-rev-1" || so["policy_group"] != "prod" || so["server"] != testServerURL {
		t.Errorf("include source_options = %v", so)
	}
	for name, id := range map[string]string{"base": "id-2.1.0", "util": "id-1.0.0"} {
		cl := lock.CookbookLocks[name]
		if cl.CacheKey != name+"-"+id || cl.SourceOptions["chef_server_artifact"] != testServerURL || cl.SourceOptions["identifier"] != id {
			t.Errorf("cookbook_locks[%s] = %+v, want the included artifact %s", name, cl, id)
		}
	}
	if v := lock.CookbookLocks["util"].Version; v != "1.0.0" {
		t.Errorf("util = %s, want the included lock's 1.0.0 over the universe's 1.1.0", v)
	}
	if !slices.Equal(srv.fetched, []string{"app-0.3.0"}) {
		t.Errorf("fetched %v, want only app from /cookbooks", srv.fetched)
	}
}

// TestResolveIncludedCookbooksOnly keeps an include to its cookbooks: the
// versions and artifacts are the same as a chef-cli include, but neither the
// run list nor the attributes of the included lock reach the lock.
func TestResolveIncludedCookbooksOnly(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse(), locks: map[string][]byte{"base@prod": []byte(includedBaseLock)}}
	_, lock := resolveTest(t, srv, includeEval(), Options{IncludedCookbooksOnly: true})

	if !slices.Equal(lock.RunList, []string{"recipe[app::default]"}) {
		t.Errorf("run_list = %v, want only the policy's own", lock.RunList)
	}
	if lock.DefaultAttributes["base"] != nil {
		t.Errorf("default_attributes = %v, want only the policy's own", lock.DefaultAttributes)
	}
	if len(lock.IncludedPolicyLocks) != 1 {
		t.Errorf("included_policy_locks = %+v, want the include recorded", lock.IncludedPolicyLocks)
	}
	if cl := lock.CookbookLocks["util"]; cl.Version != "1.0.0" || cl.SourceOptions["identifier"] != "id-1.0.0" {
		t.Errorf("util = %+v, want the included artifact", cl)
	}
}

// TestResolveIncludeAttributeConflict fails the way chef-cli's
// AttributeMergeChecker does when an include sets an attribute to a value
// the policy disagrees with.
func TestResolveIncludeAttributeConflict(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse(), locks: map[string][]byte{"base@prod": []byte(includedBaseLock)}}
	eval := includeEval()
	eval.DefaultAttributes["shared"] = "different"
	_, err := Resolve(context.Background(), eval, Options{Server: srv.open})
	if err == nil || !strings.Contains(err.Error(), "[shared]") || !strings.Contains(err.Error(), "base") {
		t.Fatalf("err = %v, want a conflict on [shared] naming base", err)
	}
}

// TestResolveIncludeByRevision reads the included lock at the pinned
// revision rather than from the group.
func TestResolveIncludeByRevision(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse(), locks: map[string][]byte{"base#base-rev-1": []byte(includedBaseLock)}}
	eval := includeEval()
	eval.IncludedPolicies[0].SourceOptions = map[string]any{"server": testServerURL, "policy_revision_id": "base-rev-1"}
	_, lock := resolveTest(t, srv, eval, Options{})
	if so := lock.IncludedPolicyLocks[0].SourceOptions; so["policy_group"] != nil || so["policy_revision_id"] != "base-rev-1" {
		t.Errorf("include source_options = %v, want the revision and no group", so)
	}
}

// TestResolveServerNeedsConnection reports a Policyfile that names a server
// when the caller set up no way to reach one.
func TestResolveServerNeedsConnection(t *testing.T) {
	eval := &rubyeval.EvaluatedPolicy{
		Name:           "app",
		RunList:        []string{"app"},
		DefaultSources: []rubyeval.DefaultSource{{Type: "chef_server", URI: testServerURL}},
	}
	_, err := Resolve(context.Background(), eval, Options{})
	if err == nil || !strings.Contains(err.Error(), testServerURL) {
		t.Fatalf("err = %v, want one naming the server", err)
	}
}

// TestResolveMissingCookbookNamesSources explains which sources we resolve
// when no source has a required cookbook.
func TestResolveMissingCookbookNamesSources(t *testing.T) {
	srv := &fakeServer{t: t, universe: testUniverse()}
	eval := &rubyeval.EvaluatedPolicy{
		Name:           "app",
		RunList:        []string{"nope::default"},
		DefaultSources: []rubyeval.DefaultSource{{Type: "chef_server", URI: testServerURL}},
	}
	_, err := Resolve(context.Background(), eval, Options{Server: srv.open})
	if err == nil || !strings.Contains(err.Error(), `"nope"`) || !strings.Contains(err.Error(), "path:") {
		t.Fatalf("err = %v, want one naming nope and the supported sources", err)
	}
}

// TestLoadPathInclude reads an included lock from a directory, the way
// chef-cli's LocalLockFetcher does: <name>.lock.json inside it, a 10-character
// revision prefix is enough, and each cookbook's path is rewritten relative to
// the including Policyfile.
func TestLoadPathInclude(t *testing.T) {
	golden, err := os.ReadFile("testdata/include_path/included/Policyfile.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RevisionID string `json:"revision_id"`
	}
	if err := json.Unmarshal(golden, &doc); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "policies", "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policies", "base", "base.lock.json"), golden, 0o644); err != nil {
		t.Fatal(err)
	}

	opts := newJSONObject()
	opts.set("path", "policies/base")
	opts.set("policy_revision_id", doc.RevisionID[:10])
	lock, err := loadPathInclude("base", opts, dir)
	if err != nil {
		t.Fatalf("loadPathInclude: %v", err)
	}
	if got := lock.cookbooks["base"].sourceOptions.str("path"); got != "policies/cookbooks/base" {
		t.Errorf("base path = %q, want it relative to the including Policyfile", got)
	}

	opts.set("policy_revision_id", "0000000000")
	if _, err := loadPathInclude("base", opts, dir); err == nil || !strings.Contains(err.Error(), "0000000000") {
		t.Errorf("err = %v, want a revision mismatch", err)
	}
}
