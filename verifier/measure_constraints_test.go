package verifier

import (
	"os"
	"testing"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// TestMeasureConstraints records the circuit stats for quick regression tracking.
func TestMeasureConstraints(t *testing.T) {
	if os.Getenv("DEBUG_MEASURE_CONSTRAINTS") == "" {
		t.Skip("set DEBUG_MEASURE_CONSTRAINTS=1 to measure constraint counts")
	}

	circuit, _ := loadVerifierCircuit(t, "addition_bn128", types.HashModePoseidonBN254)
	t.Logf("num_gate_constraints: %d", circuit.CommonCircuitData.NumGateConstraints)
	t.Logf("num_public_inputs: %d", circuit.CommonCircuitData.NumPublicInputs)
	t.Logf("num_lookup_selectors: %d", circuit.CommonCircuitData.NumLookupSelectors)
}
