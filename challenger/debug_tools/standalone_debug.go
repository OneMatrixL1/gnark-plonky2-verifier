package main

import (
	"fmt"
	"os"
)

// This binary is intentionally lightweight: it simply prints reminders on how to
// replay the Fiat–Shamir transcript with the reference Rust/Plonky2 tooling.
// Historically this file contained a full Go reimplementation of the Poseidon
// sponge; rebuilding that is out of scope for day-to-day debugging, but we keep
// the entry point so the old documentation links remain valid.
func main() {
	fmt.Println("Standalone challenger debug helper")
	fmt.Println("==================================")
	fmt.Println()
	fmt.Println("Use this helper as a bookmark for the original workflow:")
	fmt.Println()
	fmt.Println("  1. cd simple-plonky2-circuit-generator")
	fmt.Println("  2. DEBUG_BN254=1 VERIFY_PROOF=1 cargo run --release")
	fmt.Println("     -> replays the frozen BN128 proof and prints all challenger coins.")
	fmt.Println()
	fmt.Println("See docs/DEBUG_FROZEN_PROOF.md for the complete transcript and the")
	fmt.Println("expected beta/gamma values emitted by Plonky2.")
	fmt.Println()
	fmt.Printf("Working directory: %s\n", os.Getenv("PWD"))
}
