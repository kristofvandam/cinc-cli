package policyfile

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	cinc "github.com/cinc-project/cinc-api"

	"github.com/cinc-project/cinc-cli/cli/policyfile/resolver"
)

// ChefServer is the resolver.ChefServer for one server, over the Fetcher's
// cinc-api client: the universe is read once, and cookbooks and cookbook
// artifacts are cached under the Fetcher's cache root.
type ChefServer struct {
	Fetcher *Fetcher

	once     sync.Once
	universe cinc.Universe
	err      error
}

var _ resolver.ChefServer = (*ChefServer)(nil)

// Universe returns the server's cookbook universe, fetched on first use.
func (s *ChefServer) Universe(ctx context.Context) (cinc.Universe, error) {
	s.once.Do(func() {
		if s.Fetcher.Chef == nil {
			s.err = fmt.Errorf("a chef_server source requires a configured server connection")
			return
		}
		s.universe, _, s.err = s.Fetcher.Chef.Universe.Get(ctx)
	})
	return s.universe, s.err
}

// FetchCookbook returns the cached directory of a cookbook version.
func (s *ChefServer) FetchCookbook(ctx context.Context, name, version string) (string, error) {
	return s.Fetcher.EnsureServerCookbook(ctx, name, version)
}

// FetchCookbookArtifact returns the cached directory of a cookbook artifact.
func (s *ChefServer) FetchCookbookArtifact(ctx context.Context, name, identifier string) (string, error) {
	return s.Fetcher.EnsureServerArtifact(ctx, name, identifier)
}

// FetchPolicyLock reads a policy lock: the revision ref names, or the one its
// group currently points at.
func (s *ChefServer) FetchPolicyLock(ctx context.Context, ref resolver.PolicyRef) ([]byte, error) {
	if s.Fetcher.Chef == nil {
		return nil, fmt.Errorf("an include_policy server: source requires a configured server connection")
	}
	var (
		lock *cinc.PolicyRevision
		err  error
	)
	if ref.RevisionID != "" {
		lock, _, err = s.Fetcher.Chef.Policies.GetRevision(ctx, ref.Name, ref.RevisionID)
	} else {
		lock, _, err = s.Fetcher.Chef.PolicyGroups.GetPolicy(ctx, ref.Group, ref.Name)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(lock)
}
