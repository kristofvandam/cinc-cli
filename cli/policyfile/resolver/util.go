package resolver

import (
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cinc-project/cinc-cli/cli/policyfile/rubyeval"
)

// runListWrapperRE matches a run_list item wrapped as recipe[...] or role[...].
var runListWrapperRE = regexp.MustCompile(`^(recipe|role)\[(.+)\]$`)

// normalizeRunList rewrites run_list items into chef's locked recipe[...] form,
// mirroring PolicyfileCompiler#normalize_recipe: the qualifier and any @version
// are stripped to the bare name, a recipe without "::" gets "::default"
// appended, and the result is wrapped as "recipe[<name>]". It returns a slice
// of strings as `any` values for direct use in the lock object.
func normalizeRunList(items []string) []any {
	strs := normalizeRunListStrings(items)
	out := make([]any, len(strs))
	for i, s := range strs {
		out[i] = s
	}
	return out
}

// normalizeRunListStrings is normalizeRunList but typed as []string, for
// building the canonical revision string.
func normalizeRunListStrings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, "recipe["+recipeName(item)+"]")
	}
	return out
}

// recipeName extracts the fully-qualified recipe name (cookbook::recipe) from a
// run_list item, appending "::default" when the item names only a cookbook.
func recipeName(item string) string {
	name := runListItemName(item)
	if !strings.Contains(name, "::") {
		name += "::default"
	}
	return name
}

// runListItemName strips a recipe[...] / role[...] wrapper and any @version
// suffix from a run_list item, mirroring Chef::RunList::RunListItem#name.
func runListItemName(item string) string {
	s := item
	if m := runListWrapperRE.FindStringSubmatch(s); m != nil {
		s = m[2]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

// runListItemKey identifies a run_list item the way Chef::RunList::RunListItem
// equality does: by type, name and version, so "app" and "recipe[app]" are the
// same item while "app" and "app::default" are not.
func runListItemKey(item string) string {
	typ, s := "recipe", item
	if m := runListWrapperRE.FindStringSubmatch(s); m != nil {
		typ, s = m[1], m[2]
	}
	name, version, _ := strings.Cut(s, "@")
	return typ + "\x00" + name + "\x00" + version
}

// runListCookbookName returns the cookbook a run_list item maps to (the part
// before "::"). chef does not special-case roles in a Policyfile run_list — a
// role[web] item yields a cookbook demand "web" exactly as recipe[web] would —
// so neither do we, which keeps resolution (and its failure modes) identical.
func runListCookbookName(item string) string {
	name := runListItemName(item)
	if before, _, ok := strings.Cut(name, "::"); ok {
		return before
	}
	return name
}

func sortedCookbookNames(m map[string]rubyeval.CookbookSpec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedVersionKeys(m map[string]Version) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// sortJSONObjectKeys sorts an object's key order lexically in place, matching
// chef's `.sort.to_h` on the dependencies map.
func sortJSONObjectKeys(o *jsonObject) {
	sort.Strings(o.keys)
}
