package challenger

import "testing"

// TestStandaloneChallenger documents the workflow for replaying Fiat–Shamir traces.
// The actual heavy lifting happens in simple-plonky2-circuit-generator when VERIFY_PROOF=1.
func TestStandaloneChallenger(t *testing.T) {
	t.Skip("run `DEBUG_BN254=1 VERIFY_PROOF=1 cargo run --release` in simple-plonky2-circuit-generator to replay the challenger trace")
}
