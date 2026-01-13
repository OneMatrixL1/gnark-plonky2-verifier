package types

import (
	"encoding/json"
	"io"
	"os"
)

// HashValue can deserialize from either:
// - BN128 format: single decimal string "123456789..."
// - Goldilocks format: array of 4 u64 [u64, u64, u64, u64]
type HashValue struct {
	// For BN128: the decimal string representation
	// For Goldilocks: we convert the 4 u64 array to a string for uniform handling
	Value string
	// Raw Goldilocks values (only set if parsed from array format)
	GoldilocksValues []uint64
	// True if this was parsed from Goldilocks format
	IsGoldilocks bool
}

func (h *HashValue) UnmarshalJSON(data []byte) error {
	// Try string first (BN128 format)
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		h.Value = str
		h.IsGoldilocks = false
		return nil
	}

	// Try array of 4 u64 (Goldilocks format)
	var arr []uint64
	if err := json.Unmarshal(data, &arr); err == nil {
		h.GoldilocksValues = arr
		h.IsGoldilocks = true
		// Store as empty string - the variable deserializer will handle conversion
		h.Value = ""
		return nil
	}

	return json.Unmarshal(data, &str) // Return original error
}

// String returns the BN128 string value (only valid for BN128 format)
func (h *HashValue) String() string {
	return h.Value
}

type ProofWithPublicInputsRaw struct {
	Proof struct {
		WiresCap                  []HashValue `json:"wires_cap"`
		PlonkZsPartialProductsCap []HashValue `json:"plonk_zs_partial_products_cap"`
		QuotientPolysCap          []HashValue `json:"quotient_polys_cap"`
		Openings                  struct {
			Constants       [][]uint64 `json:"constants"`
			PlonkSigmas     [][]uint64 `json:"plonk_sigmas"`
			Wires           [][]uint64 `json:"wires"`
			PlonkZs         [][]uint64 `json:"plonk_zs"`
			PlonkZsNext     [][]uint64 `json:"plonk_zs_next"`
			PartialProducts [][]uint64 `json:"partial_products"`
			QuotientPolys   [][]uint64 `json:"quotient_polys"`
			LookupZs        [][]uint64 `json:"lookup_zs"`
			LookupZsNext    [][]uint64 `json:"lookup_zs_next"`
		} `json:"openings"`
		OpeningProof struct {
			CommitPhaseMerkleCaps [][]HashValue `json:"commit_phase_merkle_caps"`
			QueryRoundProofs      []struct {
				InitialTreesProof struct {
					EvalsProofs []EvalProofRaw `json:"evals_proofs"`
				} `json:"initial_trees_proof"`
				Steps []struct {
					Evals       [][]uint64 `json:"evals"`
					MerkleProof struct {
						Siblings []HashValue `json:"siblings"`
					} `json:"merkle_proof"`
				} `json:"steps"`
			} `json:"query_round_proofs"`
			FinalPoly struct {
				Coeffs [][]uint64 `json:"coeffs"`
			} `json:"final_poly"`
			PowWitness uint64 `json:"pow_witness"`
		} `json:"opening_proof"`
	} `json:"proof"`
	PublicInputs []uint64 `json:"public_inputs"`
}

type EvalProofRaw struct {
	LeafElements []uint64
	MerkleProof  MerkleProofRaw
}

func (e *EvalProofRaw) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &[]interface{}{&e.LeafElements, &e.MerkleProof})
}

type MerkleProofRaw struct {
	Hash []HashValue
}

func (m *MerkleProofRaw) UnmarshalJSON(data []byte) error {
	type SiblingObject struct {
		Siblings []HashValue `json:"siblings"`
	}

	var siblings SiblingObject
	if err := json.Unmarshal(data, &siblings); err != nil {
		return err
	}

	m.Hash = make([]HashValue, len(siblings.Siblings))
	copy(m.Hash[:], siblings.Siblings)

	return nil
}

type ProofChallengesRaw struct {
	PlonkBetas    []uint64 `json:"plonk_betas"`
	PlonkGammas   []uint64 `json:"plonk_gammas"`
	PlonkAlphas   []uint64 `json:"plonk_alphas"`
	PlonkZeta     []uint64 `json:"plonk_zeta"`
	FriChallenges struct {
		FriAlpha        []uint64   `json:"fri_alpha"`
		FriBetas        [][]uint64 `json:"fri_betas"`
		FriPowResponse  uint64     `json:"fri_pow_response"`
		FriQueryIndices []uint64   `json:"fri_query_indices"`
	} `json:"fri_challenges"`
}

type VerifierOnlyCircuitDataRaw struct {
	ConstantsSigmasCap []HashValue `json:"constants_sigmas_cap"`
	CircuitDigest      HashValue   `json:"circuit_digest"`
}

func ReadProofWithPublicInputs(path string) ProofWithPublicInputsRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw ProofWithPublicInputsRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}

func ReadVerifierOnlyCircuitData(path string) VerifierOnlyCircuitDataRaw {
	jsonFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	defer jsonFile.Close()
	rawBytes, _ := io.ReadAll(jsonFile)

	var raw VerifierOnlyCircuitDataRaw
	err = json.Unmarshal(rawBytes, &raw)
	if err != nil {
		panic(err)
	}

	return raw
}
