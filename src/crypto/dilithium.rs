//! Dilithium (ML-DSA-65) post-quantum signatures.
//!
//! Compiled only with the `pq` feature (requires system liboqs). Otherwise each
//! operation returns [`SpectrumError::PqLayerUnavailable`].

use crate::error::{Result, SpectrumError};
#[cfg(feature = "pq")]
use crate::types::DILITHIUM_ALGORITHM;

/// Generate a Dilithium (public, secret) keypair.
pub fn dilithium_generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "pq")]
    {
        let sig = oqs::sig::Sig::new(DILITHIUM_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let (pk, sk) = sig
            .keypair()
            .map_err(|_| SpectrumError::DilithiumKeyGenerationFailed)?;
        Ok((pk.into_vec(), sk.into_vec()))
    }

    #[cfg(not(feature = "pq"))]
    {
        Err(SpectrumError::PqLayerUnavailable)
    }
}

/// Sign a message.
pub fn dilithium_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "pq")]
    {
        let sig = oqs::sig::Sig::new(DILITHIUM_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let sk = sig
            .secret_key_from_bytes(secret_key)
            .ok_or(SpectrumError::PqInvalidInput {
                expected: "Dilithium3 secret key".to_string(),
            })?;
        sig.sign(message, sk)
            .map(|s| s.into_vec())
            .map_err(|e| SpectrumError::SignatureFailed(e.to_string()))
    }

    #[cfg(not(feature = "pq"))]
    {
        let _ = (message, secret_key);
        Err(SpectrumError::PqLayerUnavailable)
    }
}

/// Verify a signature. Returns `Ok(true)` only when the signature is valid;
/// a structurally valid but incorrect signature yields `Ok(false)` — only
/// malformed keys/schemes yield `Err`.
pub fn dilithium_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    #[cfg(feature = "pq")]
    {
        let sig = oqs::sig::Sig::new(DILITHIUM_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let signature =
            sig.signature_from_bytes(signature)
                .ok_or(SpectrumError::PqInvalidInput {
                    expected: "Dilithium3 signature".to_string(),
                })?;
        let pk = sig
            .public_key_from_bytes(public_key)
            .ok_or(SpectrumError::PqInvalidInput {
                expected: "Dilithium3 public key".to_string(),
            })?;
        Ok(sig.verify(message, signature, pk).is_ok())
    }

    #[cfg(not(feature = "pq"))]
    {
        let _ = (message, signature, public_key);
        Err(SpectrumError::PqLayerUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "pq")]
    use crate::utils::hashing::compute_sha256;

    #[test]
    fn pq_layer_semantics() {
        #[cfg(not(feature = "pq"))]
        assert!(matches!(
            dilithium_generate_keypair(),
            Err(SpectrumError::PqLayerUnavailable)
        ));

        // When the PQ layer IS built, a sign/verify round trip must hold.
        #[cfg(feature = "pq")]
        {
            let (pk, sk) = dilithium_generate_keypair().unwrap();
            let msg = compute_sha256(b"payload");
            let sig = dilithium_sign(&msg, &sk).unwrap();
            assert!(dilithium_verify(&msg, &sig, &pk).unwrap());
        }
    }
}
