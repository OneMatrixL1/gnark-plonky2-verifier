package verifier

import (
	"os"
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// TestTraceChallenges prints the Fiat–Shamir challenges for manual comparison with Plonky2.
func TestTraceChallenges(t *testing.T) {
	if os.Getenv("DEBUG_TRACE_CHALLENGES") == "" {
		t.Skip("set DEBUG_TRACE_CHALLENGES=1 to dump challenger transcript")
	}
	os.Setenv("DEBUG_BN254_TRACE", "1")
	runDebugCircuit(t, "addition_bn128", types.HashModePoseidonBN254)
}
