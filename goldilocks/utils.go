package goldilocks

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

func StrArrayToBigIntArray(input []string) []big.Int {
	var output []big.Int
	for i := 0; i < len(input); i++ {
		a := new(big.Int)
		a, _ = a.SetString(input[i], 10)
		output = append(output, *a)
	}
	return output
}

func StrArrayToFrontendVariableArray(input []string) []frontend.Variable {
	var output []frontend.Variable
	for i := 0; i < len(input); i++ {
		output = append(output, frontend.Variable(input[i]))
	}
	return output
}

func Uint64ArrayToVariableArray(input []uint64) []Variable {
	var output []Variable
	for i := 0; i < len(input); i++ {
		// Reduce value mod Goldilocks modulus at deserialization time
		// This matches Rust's GoldilocksField::from_canonical_u64 behavior
		// and avoids expensive in-circuit reduction
		val := input[i] % MODULUS.Uint64()
		output = append(output, NewVariable(val))
	}
	return output
}

func Uint64ArrayToQuadraticExtension(input []uint64) QuadraticExtensionVariable {
	// Reduce values mod Goldilocks modulus at deserialization time
	val0 := input[0] % MODULUS.Uint64()
	val1 := input[1] % MODULUS.Uint64()
	return NewQuadraticExtensionVariable(NewVariable(val0), NewVariable(val1))
}

func Uint64ArrayToQuadraticExtensionArray(input [][]uint64) []QuadraticExtensionVariable {
	var output []QuadraticExtensionVariable
	for i := 0; i < len(input); i++ {
		// Reduce values mod Goldilocks modulus at deserialization time
		val0 := input[i][0] % MODULUS.Uint64()
		val1 := input[i][1] % MODULUS.Uint64()
		output = append(output, NewQuadraticExtensionVariable(NewVariable(val0), NewVariable(val1)))
	}
	return output
}

type bitDecompChecker struct {
	api frontend.API
}

func (pl bitDecompChecker) Check(v frontend.Variable, nbBits int) {
	bits.ToBinary(pl.api, v, bits.WithNbDigits(nbBits))
}
