package verifier_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

// TestAdditionVerifier is the legacy test (uses Goldilocks Poseidon by default)
func TestAdditionVerifier(t *testing.T) {
	TestAdditionVerifier_Goldilocks(t)
}

// TestAdditionVerifier_Goldilocks tests verification with Goldilocks Poseidon
// Uses testdata/addition/ with standard Plonky2 hash (emulated, ~24M constraints)
func TestAdditionVerifier_Goldilocks(t *testing.T) {
	assert := test.NewAssert(t)

	plonky2Circuit := "addition"
	commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonGoldilocks,
	}

	witness := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonGoldilocks,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// TestAdditionVerifier_BN254 tests verification with BN254 Poseidon
// Uses testdata/addition_bn128/ with BN254 Poseidon (native, ~5M constraints)
func TestAdditionVerifier_BN254(t *testing.T) {
	assert := test.NewAssert(t)

	plonky2Circuit := "addition_bn128"
	commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonBN254,
	}

	witness := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonBN254,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// TestRecursiveVerifier_Goldilocks tests verification of recursive proof
// Uses testdata/recursive_bn128/ with standard Goldilocks Poseidon
// This proof aggregates Sum, Max, and Merkle operators from rust-prover
func TestRecursiveVerifier_Goldilocks(t *testing.T) {
	assert := test.NewAssert(t)

	plonky2Circuit := "recursive_bn128"
	commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonGoldilocks,
	}

	witness := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonGoldilocks,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// TestRecursiveVerifier_BN254_Wrapped tests verification of BN128-wrapped recursive proof
// Uses testdata/recursive_bn128_wrapped/ with BN254 Poseidon (native, ~5M constraints)
// This proof wraps a Goldilocks recursive proof with BN128 for efficient gnark verification
func TestRecursiveVerifier_BN254_Wrapped(t *testing.T) {
	assert := test.NewAssert(t)

	plonky2Circuit := "recursive_bn128_wrapped"
	commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonBN254,
	}

	witness := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                types.HashModePoseidonBN254,
	}

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}