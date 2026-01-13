package types

// HashMode specifies which Poseidon hash implementation to use
type HashMode string

const (
	// HashModePoseidonGoldilocks uses Poseidon hash over Goldilocks field
	// This is the standard Plonky2 configuration (~24M constraints in gnark)
	HashModePoseidonGoldilocks HashMode = "poseidon_goldilocks"

	// HashModePoseidonBN254 uses Poseidon hash over BN254 scalar field
	// This is the low-constraint configuration (~5M constraints in gnark)
	// Using native BN254 Poseidon reduces constraints significantly
	HashModePoseidonBN254 HashMode = "poseidon_bn254"
)
