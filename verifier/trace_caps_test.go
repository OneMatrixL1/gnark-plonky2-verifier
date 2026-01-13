package verifier

import (
	"os"
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// TestTraceCaps dumps Merkle caps so they can be compared with the standalone tools.
func TestTraceCaps(t *testing.T) {
	if os.Getenv("DEBUG_TRACE_CAPS") == "" {
		t.Skip("set DEBUG_TRACE_CAPS=1 to inspect Merkle cap observations")
	}
	os.Setenv("DEBUG_BN254_TRACE", "1")
	runDebugCircuit(t, "addition_bn128", types.HashModePoseidonBN254)
}
