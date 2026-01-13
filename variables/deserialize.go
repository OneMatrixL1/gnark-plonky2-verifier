package variables

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
)

// HashValueToGoldilocksHashOut converts a HashValue to a GoldilocksHashOut
// Handles both BN128 format (decimal string stored as 4 chunks) and Goldilocks format (4 u64 array)
func HashValueToGoldilocksHashOut(h types.HashValue) poseidon.GoldilocksHashOut {
	var result poseidon.GoldilocksHashOut

	if h.IsGoldilocks {
		// Goldilocks format: 4 u64 values
		for i := 0; i < 4 && i < len(h.GoldilocksValues); i++ {
			result[i] = gl.NewVariable(h.GoldilocksValues[i])
		}
	} else {
		// BN128 format: single decimal string
		// This needs to be split into 4 u64 chunks (little-endian limbs)
		hashBigInt, _ := new(big.Int).SetString(h.Value, 10)
		bytes := hashBigInt.Bytes()

		// Pad to 32 bytes if needed
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)

		// Split into 4 u64 values (big-endian order in bytes, convert to little-endian limbs)
		for i := 0; i < 4; i++ {
			var val uint64
			for j := 0; j < 8; j++ {
				val = (val << 8) | uint64(padded[i*8+j])
			}
			result[3-i] = gl.NewVariable(val) // Reverse order for little-endian limbs
		}
	}
	return result
}

// HashValueToVariable converts a HashValue to a gnark Variable (BN254HashOut)
// Handles both BN128 format (decimal string) and Goldilocks format (4 u64 array)
func HashValueToVariable(h types.HashValue) poseidon.BN254HashOut {
	if h.IsGoldilocks {
		// Goldilocks format: 4 u64 values representing a Goldilocks hash
		// Convert to a single big.Int by treating as little-endian limbs
		result := new(big.Int)
		multiplier := new(big.Int).SetUint64(1)
		shift := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64

		for _, val := range h.GoldilocksValues {
			term := new(big.Int).SetUint64(val)
			term.Mul(term, multiplier)
			result.Add(result, term)
			multiplier.Mul(multiplier, shift)
		}
		return frontend.Variable(result)
	}

	// BN128 format: single decimal string
	hashBigInt, _ := new(big.Int).SetString(h.Value, 10)
	return frontend.Variable(hashBigInt)
}

func DeserializeMerkleCap(merkleCapRaw []types.HashValue) FriMerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]poseidon.GoldilocksHashOut, n)
	for i := 0; i < n; i++ {
		merkleCap[i] = HashValueToGoldilocksHashOut(merkleCapRaw[i])
	}
	return merkleCap
}

func DeserializeMerkleProof(merkleProofRaw struct{ Siblings []types.HashValue }) FriMerkleProof {
	n := len(merkleProofRaw.Siblings)
	var mp FriMerkleProof
	mp.Siblings = make([]poseidon.GoldilocksHashOut, n)
	for i := 0; i < n; i++ {
		mp.Siblings[i] = HashValueToGoldilocksHashOut(merkleProofRaw.Siblings[i])
	}
	return mp
}

func DeserializeOpeningSet(openingSetRaw struct {
	Constants       [][]uint64
	PlonkSigmas     [][]uint64
	Wires           [][]uint64
	PlonkZs         [][]uint64
	PlonkZsNext     [][]uint64
	PartialProducts [][]uint64
	QuotientPolys   [][]uint64
	LookupZs        [][]uint64
	LookupZsNext    [][]uint64
}) OpeningSet {
	return OpeningSet{
		Constants:       gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
		LookupZs:        gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.LookupZs),
		LookupZsNext:    gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.LookupZsNext),
	}
}

func HashValueArrayToGoldilocksHashOutArray(rawHashes []types.HashValue) []poseidon.GoldilocksHashOut {
	hashes := make([]poseidon.GoldilocksHashOut, len(rawHashes))
	for i := 0; i < len(rawHashes); i++ {
		hashes[i] = HashValueToGoldilocksHashOut(rawHashes[i])
	}
	return hashes
}

func DeserializeFriProof(openingProofRaw struct {
	CommitPhaseMerkleCaps [][]types.HashValue
	QueryRoundProofs      []struct {
		InitialTreesProof struct {
			EvalsProofs []types.EvalProofRaw
		}
		Steps []struct {
			Evals       [][]uint64
			MerkleProof struct {
				Siblings []types.HashValue
			}
		}
	}
	FinalPoly struct {
		Coeffs [][]uint64
	}
	PowWitness uint64
}) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]FriMerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = HashValueArrayToGoldilocksHashOutArray(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]FriEvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = gl.Uint64ArrayToVariableArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = HashValueArrayToGoldilocksHashOutArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = HashValueArrayToGoldilocksHashOutArray(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(raw types.ProofWithPublicInputsRaw) ProofWithPublicInputs {
	debugEnabled := os.Getenv("DEBUG_DESERIALIZE") != ""

	if debugEnabled {
		fmt.Println("\n=== Deserializing ProofWithPublicInputs ===")
		fmt.Printf("FinalPoly coeffs from JSON (first 3):\n")
		for i := 0; i < 3 && i < len(raw.Proof.OpeningProof.FinalPoly.Coeffs); i++ {
			fmt.Printf("  coeff[%d]: %v\n", i, raw.Proof.OpeningProof.FinalPoly.Coeffs[i])
		}
	}

	var proofWithPis ProofWithPublicInputs
	// Convert BN254 strings (from circuit generator)
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap(raw.Proof.WiresCap)
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap(raw.Proof.PlonkZsPartialProductsCap)
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap(raw.Proof.QuotientPolysCap)
	proofWithPis.Proof.Openings = DeserializeOpeningSet(struct {
		Constants       [][]uint64
		PlonkSigmas     [][]uint64
		Wires           [][]uint64
		PlonkZs         [][]uint64
		PlonkZsNext     [][]uint64
		PartialProducts [][]uint64
		QuotientPolys   [][]uint64
		LookupZs        [][]uint64
		LookupZsNext    [][]uint64
	}(raw.Proof.Openings))
	proofWithPis.Proof.OpeningProof = DeserializeFriProof(struct {
		CommitPhaseMerkleCaps [][]types.HashValue
		QueryRoundProofs      []struct {
			InitialTreesProof struct {
				EvalsProofs []types.EvalProofRaw
			}
			Steps []struct {
				Evals       [][]uint64
				MerkleProof struct {
					Siblings []types.HashValue
				}
			}
		}
		FinalPoly  struct{ Coeffs [][]uint64 }
		PowWitness uint64
	}(raw.Proof.OpeningProof))
	proofWithPis.PublicInputs = gl.Uint64ArrayToVariableArray(raw.PublicInputs)

	return proofWithPis
}

func DeserializeVerifierOnlyCircuitData(raw types.VerifierOnlyCircuitDataRaw) VerifierOnlyCircuitData {
	var verifierOnlyCircuitData VerifierOnlyCircuitData
	verifierOnlyCircuitData.ConstantSigmasCap = DeserializeMerkleCap(raw.ConstantsSigmasCap)
	verifierOnlyCircuitData.CircuitDigest = HashValueToGoldilocksHashOut(raw.CircuitDigest)
	return verifierOnlyCircuitData
}
