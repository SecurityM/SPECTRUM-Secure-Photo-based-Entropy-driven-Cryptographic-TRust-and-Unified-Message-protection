//! NTRU-Prime (sntrup761) post-quantum KEM.
//!
//! Compiled only with the `pq` feature (which pulls in `oqs` and therefore
//! requires the system liboqs library). When absent, every operation returns
//! [`SpectrumError::PqLayerUnavailable`].

use crate::error::{Result, SpectrumError};
#[cfg(feature = "pq")]
use crate::types::NTRU_ALGORITHM;

/// Generate an NTRU-Prime (public, secret) keypair.
pub fn ntru_generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "pq")]
    {
        let kem = oqs::kem::Kem::new(NTRU_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| SpectrumError::NtruKeyGenerationFailed)?;
        Ok((pk.into_vec(), sk.into_vec()))
    }

    #[cfg(not(feature = "pq"))]
    {
        err_pq()
    }
}

/// Encapsulate a shared secret to `public_key`; returns (shared_secret, ciphertext).
pub fn ntru_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "pq")]
    {
        let kem = oqs::kem::Kem::new(NTRU_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let pk = kem
            .public_key_from_bytes(public_key)
            .ok_or(SpectrumError::PqInvalidInput {
                expected: "NTRU-Prime public key".to_string(),
            })?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|e| SpectrumError::EncapsulationFailed(e.to_string()))?;
        Ok((ss.into_vec(), ct.into_vec()))
    }

    #[cfg(not(feature = "pq"))]
    {
        let _ = public_key;
        err_pq()
    }
}

/// Decapsulate the shared secret from `ciphertext` using `secret_key`.
pub fn ntru_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "pq")]
    {
        let kem = oqs::kem::Kem::new(NTRU_ALGORITHM)
            .map_err(|e| SpectrumError::PqAlgorithmNotFound(e.to_string()))?;
        let sk = kem
            .secret_key_from_bytes(secret_key)
            .ok_or(SpectrumError::PqInvalidInput {
                expected: "NTRU-Prime secret key".to_string(),
            })?;
        let ct = kem
            .ciphertext_from_bytes(ciphertext)
            .ok_or(SpectrumError::PqInvalidInput {
                expected: "NTRU-Prime ciphertext".to_string(),
            })?;
        let ss = kem
            .decapsulate(sk, ct)
            .map_err(|e| SpectrumError::DecapsulationFailed(e.to_string()))?;
        Ok(ss.into_vec())
    }

    #[cfg(not(feature = "pq"))]
    {
        let _ = (secret_key, ciphertext);
        err_pq()
    }
}

#[cfg(not(feature = "pq"))]
fn err_pq<T>() -> Result<T> {
    Err(SpectrumError::PqLayerUnavailable)
}

#[cfg(test)]
mod tests {
    // Fully qualified paths: with the `pq` feature no assertion survives
    // compilation here, so a glob import would be an unused-import warning.

    #[test]
    fn pq_layer_semantics() {
        // With no `pq` feature, operations must fail gracefully.
        #[cfg(not(feature = "pq"))]
        assert!(matches!(
            super::ntru_generate_keypair(),
            Err(crate::error::SpectrumError::PqLayerUnavailable)
        ));
        #[cfg(not(feature = "pq"))]
        assert!(matches!(
            super::ntru_encapsulate(&[]),
            Err(crate::error::SpectrumError::PqLayerUnavailable)
        ));
    }
}
