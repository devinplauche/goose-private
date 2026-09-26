//! FIPS 140-3 provider activation test for the on-prem build.
//!
//! Verifies that the FIPS-validated crypto provider (AWS-LC FIPS module,
//! FIPS 140-3 cert #4816) actually installs and reports active at runtime —
//! not just that the feature compiles. The module's power-on self-tests run
//! during provider installation; if they fail, no FIPS provider becomes the
//! default, and this test catches it.
//!
//! Only compiled with `--features onprem` (which implies `fips`).

#![cfg(feature = "onprem")]

use warmachine::onprem::{init_fips_crypto, is_fips_provider_active};

/// The FIPS provider must install and report active. This exercises the
/// module's power-on self-tests: a POST failure leaves the default provider
/// unset, failing the assertion.
#[test]
fn fips_provider_activates() {
    init_fips_crypto();
    assert!(
        is_fips_provider_active(),
        "FIPS-validated crypto provider must be active in on-prem builds; \
         the AWS-LC FIPS module failed to install (power-on self-test failure?)"
    );
}

/// Activation must be idempotent: calling init twice must not disturb the
/// active FIPS provider (startup code and tests may both call it).
#[test]
fn fips_provider_activation_is_idempotent() {
    init_fips_crypto();
    init_fips_crypto();
    assert!(
        is_fips_provider_active(),
        "FIPS provider must stay active across repeated init calls"
    );
}
