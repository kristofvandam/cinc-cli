package resolver

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	cinc "github.com/cinc-project/cinc-api"

	"github.com/cinc-project/cinc-cli/cli/policyfile/rubyeval"
)

// ChefServer is the Cinc/Chef Infra Server a Policyfile resolves against: the
// cookbook universe behind `default_source :chef_server`, the cookbooks and
// cookbook artifacts it serves, and the policy locks an `include_policy ...,
// server:` names. Resolve fetches cookbooks concurrently, so an
// implementation must be safe for concurrent use.
type ChefServer interface {
	// Universe returns every cookbook version the server offers, with each
	// version's dependencies (GET /universe).
	Universe(ctx context.Context) (cinc.Universe, error)
	// FetchCookbook makes a cookbook version available on disk and returns
	// the cookbook's root directory.
	FetchCookbook(ctx context.Context, name, version string) (string, error)
	// FetchCookbookArtifact does the same for a cookbook artifact, which a
	// policy lock pins by content identifier.
	FetchCookbookArtifact(ctx context.Context, name, identifier string) (string, error)
	// FetchPolicyLock returns the raw JSON of a policy lock document.
	FetchPolicyLock(ctx context.Context, ref PolicyRef) ([]byte, error)
}

// PolicyRef names one policy lock on a server: the lock at RevisionID when it
// is set, otherwise the one Group currently points at.
type PolicyRef struct {
	Name       string
	Group      string
	RevisionID string
}

// servers memoizes Options.Server per URL for one Resolve, since cookbooks
// are located concurrently and a policy usually names one server many times.
type servers struct {
	open func(url string) (ChefServer, error)

	mu    sync.Mutex
	byURL map[string]ChefServer
}

func (s *servers) get(url string) (ChefServer, error) {
	if s.open == nil {
		return nil, fmt.Errorf("cinc: your Policyfile uses the server at %s, but no server connection was set up to resolve it", url)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv, ok := s.byURL[url]; ok {
		return srv, nil
	}
	srv, err := s.open(url)
	if err != nil {
		return nil, err
	}
	if s.byURL == nil {
		s.byURL = map[string]ChefServer{}
	}
	s.byURL[url] = srv
	return srv, nil
}

// serverUniverse converts a server's universe into solver candidates. JSON
// objects have no order, so each version's dependencies are sorted by name;
// constraints are Semverse-normalized the way chef writes them into a lock,
// and one that does not parse is kept as is for the solver to report.
func serverUniverse(u cinc.Universe) universe {
	out := make(universe, len(u))
	for name, versions := range u {
		for ver, entry := range versions {
			v, err := ParseVersion(ver)
			if err != nil {
				continue
			}
			deps := make([]rubyeval.Dependency, 0, len(entry.Dependencies))
			for _, dep := range slices.Sorted(maps.Keys(entry.Dependencies)) {
				constraint := entry.Dependencies[dep]
				if c, err := ParseConstraint(constraint); err == nil {
					constraint = normalizeConstraint(c)
				}
				deps = append(deps, rubyeval.Dependency{Name: dep, Constraint: constraint})
			}
			out[name] = append(out[name], candidate{version: v, deps: deps})
		}
	}
	return out
}

// chefServerCookbook locates a cookbook version served from url's /cookbooks,
// locked the way chef-cli's ChefServerLocation records it.
func chefServerCookbook(ctx context.Context, srv ChefServer, url, name string, v Version, deps []rubyeval.Dependency) (*cookbookInfo, error) {
	ver := v.lockString()
	dir, err := srv.FetchCookbook(ctx, name, ver)
	if err != nil {
		return nil, fmt.Errorf("cinc: cookbook %q %s from %s: %w", name, ver, url, err)
	}
	so := newJSONObject()
	so.set("chef_server", url)
	so.set("version", ver)
	return &cookbookInfo{
		name: name, version: v, verStr: ver, deps: deps, dir: dir,
		cached: true, cacheKey: name + "-" + ver, origin: url, sourceOptions: so,
	}, nil
}

// chefServerArtifact locates a cookbook artifact pinned by identifier, locked
// the way chef-cli's ChefServerArtifactLocation records it.
func chefServerArtifact(ctx context.Context, srv ChefServer, url, name, identifier string, v Version, deps []rubyeval.Dependency) (*cookbookInfo, error) {
	dir, err := srv.FetchCookbookArtifact(ctx, name, identifier)
	if err != nil {
		return nil, fmt.Errorf("cinc: cookbook artifact %q %s from %s: %w", name, identifier, url, err)
	}
	so := newJSONObject()
	so.set("chef_server_artifact", url)
	so.set("identifier", identifier)
	return &cookbookInfo{
		name: name, version: v, verStr: v.lockString(), deps: deps, dir: dir,
		cached: true, cacheKey: name + "-" + identifier, origin: url, sourceOptions: so,
	}, nil
}
