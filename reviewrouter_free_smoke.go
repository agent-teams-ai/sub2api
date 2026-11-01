package reviewrouterfixture

// reviewRouterFreeSmokeRemaining is an isolated, retained review fixture.
// It does not participate in the backend application or configure a provider.
func reviewRouterFreeSmokeRemaining() int {
	return 120 - (3 * 15)
}
