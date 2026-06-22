package container.admission

import rego.v1

# Approved registries for production deployment
approved_registries := {
    "quay.io",
    "registry.redhat.io",
}

# Approved golden base image repositories
approved_golden_bases := {
    "quay.io/aap-supply-chain/golden-ubi9-hardened",
}

# Deny images from unapproved registries
deny contains msg if {
    image := input.image_reference
    registry := split(image, "/")[0]
    not registry in approved_registries
    msg := sprintf("image '%s' is from unapproved registry '%s' -- only %v are permitted", [image, registry, approved_registries])
}

# Deny mutable tag references -- require digest pinning
deny contains msg if {
    not contains(input.image_reference, "@sha256:")
    msg := sprintf("image '%s' uses a mutable tag -- digest reference (@sha256:...) required for production", [input.image_reference])
}

# Deny unsigned images
deny contains msg if {
    not input.signature_verified
    msg := sprintf("image '%s' has no valid cosign signature -- unsigned images cannot be deployed", [input.image_reference])
}

# Deny images without SBOM attestation
deny contains msg if {
    not input.sbom_attached
    msg := sprintf("image '%s' has no SBOM attestation -- SBOM is required for production deployment", [input.image_reference])
}

# Deny images not built on an approved golden base
deny contains msg if {
    input.base_image != ""
    not input.base_image in approved_golden_bases
    msg := sprintf("image '%s' base layer '%s' is not an approved golden image -- only %v are permitted", [input.image_reference, input.base_image, approved_golden_bases])
}

# Deny images with unresolved critical CVEs
deny contains msg if {
    input.critical_cve_count > 0
    msg := sprintf("image '%s' has %d unresolved critical CVEs -- remediate before deployment", [input.image_reference, input.critical_cve_count])
}

# Final decision
decision := {
    "allowed": count(deny) == 0,
    "violations": deny,
    "image": input.image_reference,
    "checked_at": time.now_ns(),
}
