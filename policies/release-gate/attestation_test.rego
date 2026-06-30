# Unit tests for the release-gate attestation policy.
#
# Run with: conftest verify --policy policies/release-gate/
#
# Each test_* rule validates one policy behaviour. The test input
# mimics what ci-release-gate.yml assembles at runtime.

package release_gate

import rego.v1

# --- Helpers: valid baseline input ---

valid_input := {
	"signature_verified": true,
	"provenance_verified": true,
	"sbom_attested": true,
	"image_age_days": 0,
	"builder_id": "https://github.com/chrissbo/platform-golden-paths/.github/workflows/ci-post-merge.yml@refs/heads/main",
}

# --- Happy path: all checks pass ---

test_all_pass if {
	count(deny) == 0 with input as valid_input
}

# --- Signature missing ---

test_deny_no_signature if {
	msg := "Image signature verification failed — no valid Cosign keyless signature found."
	msg in deny with input as object.union(valid_input, {"signature_verified": false})
}

# --- Provenance missing ---

test_deny_no_provenance if {
	msg := "SLSA L3 provenance attestation not found or verification failed."
	msg in deny with input as object.union(valid_input, {"provenance_verified": false})
}

# --- SBOM missing ---

test_deny_no_sbom if {
	msg := "CycloneDX SBOM attestation not found — image must have an attested SBOM."
	msg in deny with input as object.union(valid_input, {"sbom_attested": false})
}

# --- Image too old ---

test_deny_stale_image if {
	msg := "Image is 10 days old (maximum allowed: 7). Rebuild or re-sign."
	msg in deny with input as object.union(valid_input, {"image_age_days": 10})
}

test_allow_7_day_old_image if {
	count(deny) == 0 with input as object.union(valid_input, {"image_age_days": 7})
}

# --- Wrong builder identity ---

test_deny_wrong_builder if {
	count(deny) > 0 with input as object.union(valid_input, {
		"builder_id": "https://github.com/attacker/evil-repo/.github/workflows/hack.yml@refs/heads/main",
	})
}

# --- Builder on non-main branch ---

test_deny_non_main_branch if {
	count(deny) > 0 with input as object.union(valid_input, {
		"builder_id": "https://github.com/chrissbo/platform-golden-paths/.github/workflows/ci-post-merge.yml@refs/heads/feature/test",
	})
}
