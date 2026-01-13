package verifier

import (
	"os"
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// TestChallengerDebug runs the BN128 verifier and prints the Fiat–Shamir coins.
func TestChallengerDebug(t *testing.T) {
	if os.Getenv("DEBUG_CHALLENGER_TRACE") == "" {
		t.Skip("set DEBUG_CHALLENGER_TRACE=1 to compare challenger outputs")
	}
	os.Setenv("DEBUG_BN254_TRACE", "1")
	runDebugCircuit(t, "addition_bn128", types.HashModePoseidonBN254)
}
