module github.com/example/app

go 1.21

require (
	github.com/pkg/errors v0.9.1
	k8s.io/apimachinery v0.0.0
)

// A LOCAL (filesystem) replacement — the module is vendored in-tree, as a
// monorepo like kubernetes does with its staging modules. No version on the RHS.
replace k8s.io/apimachinery => ./staging/apimachinery
