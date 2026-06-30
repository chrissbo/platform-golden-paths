# Release gate policy — Pipeline 4.
#
# Evaluates an attestation input document assembled by the
# ci-release-gate.yml workflow in platform-deploy. The input contains
# pre-gathered verification results (cosign verify, cosign verify-
# attestation outputs) plus image metadata.
#
# This is a real policy, not a stub. It enforces:
#   1. Image has a valid Cosign keyless signature
#   2. SLSA L3 provenance attestation exists and is valid
#   3. CycloneDX SBOM attestation exists
#   4. Image is fresh (< 7 days old)
#   5. Builder identity matches the expected workflow
#
# Run locally:
#   conftest test --policy policies/release-gate/ input.json
#
# Reference: research/cicd-toolchain/architecture/pipelines.md §Pipeline 4

package release_gate

import rego.v1

# Rule: image must have a valid Cosign keyless signature.
deny contains msg if {
	not input.signature_verified
	msg := "Image signature verification failed — no valid Cosign keyless signature found."
}

# Rule: SLSA L3 provenance attestation must exist and be valid.
deny contains msg if {
	not input.provenance_verified
	msg := "SLSA L3 provenance attestation not found or verification failed."
}

# Rule: CycloneDX SBOM attestation must exist.
deny contains msg if {
	not input.sbom_attested
	msg := "CycloneDX SBOM attestation not found — image must have an attested SBOM."
}

# Rule: image must be less than 7 days old.
deny contains msg if {
	input.image_age_days > 7
	msg := sprintf("Image is %d days old (maximum allowed: 7). Rebuild or re-sign.", [input.image_age_days])
}

# Rule: builder identity must match the expected platform workflow.
deny contains msg if {
	not startswith(input.builder_id, "https://github.com/chrissbo/platform-golden-paths/")
	msg := sprintf("Unexpected builder identity: %s. Expected workflow from chrissbo/platform-golden-paths.", [input.builder_id])
}

# Rule: builder must be on the main branch (not a feature branch).
deny contains msg if {
	not contains(input.builder_id, "@refs/heads/main")
	msg := sprintf("Builder ran on non-main ref: %s. Only main-branch builds are deployable.", [input.builder_id])
}
