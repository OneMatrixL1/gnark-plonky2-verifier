package verifier

import (
	"os"
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// TestVerifierDebugTrace reruns the addition circuit with verbose logging enabled.
// To avoid slowing down CI it only runs when DEBUG_VERIFIER_TRACE=1.
func TestVerifierDebugTrace(t *testing.T) {
	if os.Getenv("DEBUG_VERIFIER_TRACE") == "" {
		t.Skip("set DEBUG_VERIFIER_TRACE=1 to enable verbose verifier trace")
	}
	os.Setenv("DEBUG_BN254_TRACE", "1")
	runDebugCircuit(t, "addition_bn128", types.HashModePoseidonBN254)
}
