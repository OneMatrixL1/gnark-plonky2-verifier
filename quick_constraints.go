package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run quick_constraints.go <circuit_name>")
		os.Exit(1)
	}

	circuitName := os.Args[1]
	fmt.Printf("Counting constraints for: %s\n", circuitName)

	commonCircuitData := types.ReadCommonCircuitData("testdata/" + circuitName + "/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))

	// BN254 mode for fold/security circuits
	hashMode := types.HashModePoseidonBN254

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
		HashMode:                hashMode,
	}

	fmt.Println("Compiling circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Error compiling circuit:", err)
		os.Exit(1)
	}

	fmt.Printf("\nResults:\n")
	fmt.Printf("  Constraints:        %d\n", cs.GetNbConstraints())
	fmt.Printf("  Coefficients:       %d\n", cs.GetNbCoefficients())
	fmt.Printf("  Public variables:   %d\n", cs.GetNbPublicVariables())
	fmt.Printf("  Secret variables:   %d\n", cs.GetNbSecretVariables())
	fmt.Printf("  Internal variables: %d\n", cs.GetNbInternalVariables())
}
