//! Little-endian readers/writers for the SPECTRUM binary message format.

use crate::error::{Result, SpectrumError};

/// Append a `u32` as little-endian bytes.
pub fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a `u64` as little-endian bytes.
pub fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Read a `u32` at `offset`, advancing `offset` by 4. Bounds-checked.
pub fn read_u32_le(data: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes = take(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a `u64` at `offset`, advancing `offset` by 8. Bounds-checked.
pub fn read_u64_le(data: &[u8], offset: &mut usize) -> Result<u64> {
    let bytes = take(data, offset, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(arr))
}

/// Take `n` bytes (as a sub-slice) from `data` at `offset`, advancing it.
pub fn take<'a>(data: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(n)
        .ok_or_else(|| SpectrumError::MalformedMessage("length overflow".into()))?;
    if end > data.len() {
        return Err(SpectrumError::MalformedMessage(format!(
            "expected {n} bytes at offset {offset}, buffer is {} bytes",
            data.len()
        )));
    }
    let slice = &data[*offset..end];
    *offset = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_u64_roundtrip() {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, 0xDEADBEEF);
        write_u64_le(&mut buf, 0x0123456789ABCDEF);
        let mut off = 0;
        assert_eq!(read_u32_le(&buf, &mut off).unwrap(), 0xDEADBEEF);
        assert_eq!(read_u64_le(&buf, &mut off).unwrap(), 0x0123456789ABCDEF);
        assert_eq!(off, buf.len());
    }

    #[test]
    fn take_bounds_checked() {
        let data = [1u8, 2, 3];
        let mut off = 0;
        assert!(take(&data, &mut off, 4).is_err());
        assert!(take(&data, &mut off, 3).is_ok());
        assert!(take(&data, &mut off, 1).is_err());
    }
}
