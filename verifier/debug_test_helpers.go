package verifier

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

// loadVerifierCircuit constructs ExampleVerifierCircuit + witness for the requested test circuit.
// It mirrors the benchmark helper but is exposed for debug tests.
func loadVerifierCircuit(t *testing.T, circuitName string, hashMode types.HashMode) (verifierCircuit, witnessCircuit ExampleVerifierCircuit) {
	t.Helper()

	// Paths are resolved from the verifier package
	base := filepath.Join("..", "testdata", circuitName)
	proofWithPis := variables.DeserializeProofWithPublicInputs(
		types.ReadProofWithPublicInputs(filepath.Join(base, "proof_with_public_inputs.json")),
	)
	commonCircuitData := types.ReadCommonCircuitData(filepath.Join(base, "common_circuit_data.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		types.ReadVerifierOnlyCircuitData(filepath.Join(base, "verifier_only_circuit_data.json")),
	)

	circuit := ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                hashMode,
	}

	witness := ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                hashMode,
	}

	return circuit, witness
}

// runDebugCircuit executes the gnark solver (when the env var enables it) and logs progress.
func runDebugCircuit(t *testing.T, name string, hashMode types.HashMode) {
	t.Helper()
	circuit, witness := loadVerifierCircuit(t, name, hashMode)
	t.Logf("Starting debug verifier for %s (hashMode=%s)", name, hashMode)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("debug verifier failed: %v", err)
	}
	t.Log("debug verifier completed successfully")
}

// formatHash renders a Goldilocks hash in decimal form (to compare with Plonky2 traces).
func formatHash(hash [4]uint64) string {
	return fmt.Sprintf("[%d, %d, %d, %d]", hash[0], hash[1], hash[2], hash[3])
}
