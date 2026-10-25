//! Credential-decryption primitives for SAM/LSA secret analysis. Algorithms
//! stay compatible with Volatility 3's hashdump/lsadump/cachedump lineage.
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use md5::Digest;

pub(super) fn md5(data: &[u8]) -> [u8; 16] {
    let digest = md5::Md5::digest(data);
    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    out
}

pub(super) fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let mut mac = <Hmac<md5::Md5> as Mac>::new_from_slice(key)?;
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0; 16];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// RC4 keystream XOR in place.
pub(super) fn rc4(key: &[u8], data: &mut [u8]) -> Result<()> {
    ensure!(!key.is_empty() && key.len() <= 256, "RC4 密钥长度无效");
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    for byte in data.iter_mut() {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) & 0xff];
    }
    Ok(())
}

/// AES-128/256-CBC decrypt in place. `data.len()` must be a multiple of 16;
/// callers pad the trailing block themselves when the source is not aligned.
pub(super) fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    ensure!(data.len().is_multiple_of(16), "AES 数据未按块对齐");
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(GenericArray::from_slice(key));
            cbc_decrypt_all(&cipher, iv, data)
        }
        32 => {
            let cipher = aes::Aes256::new(GenericArray::from_slice(key));
            cbc_decrypt_all(&cipher, iv, data)
        }
        _ => anyhow::bail!("AES 密钥长度无效"),
    }
}

fn cbc_decrypt_all<C: BlockDecrypt>(cipher: &C, iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let mut prev = *iv;
    for chunk in data.chunks_exact_mut(16) {
        let ciphertext: [u8; 16] = chunk.try_into().expect("16-byte chunk");
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (byte, mask) in chunk.iter_mut().zip(prev.iter()) {
            *byte ^= mask;
        }
        prev = ciphertext;
    }
    Ok(())
}

/// DES-ECB decrypt of one 8-byte block.
pub(super) fn des_ecb_decrypt(key: &[u8; 8], block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == 8, "DES 块长度无效");
    let cipher = des::Des::new(GenericArray::from_slice(key));
    cipher.decrypt_block(GenericArray::from_mut_slice(block));
    Ok(())
}

/// Per-RID DES key pair used to unwrap SAM hash blobs.
pub(super) fn sid_to_key(rid: u32) -> ([u8; 8], [u8; 8]) {
    let raw = rid.to_le_bytes();
    let first = [raw[0], raw[1], raw[2], raw[3], raw[0], raw[1], raw[2]];
    let second = [raw[3], raw[0], raw[1], raw[2], raw[3], raw[0], raw[1]];
    (des_key_from_7(&first), des_key_from_7(&second))
}

/// 7 字节材料 → 8 字节 DES 密钥（SAM rid 派生与 XP LSA 机密共用）。
pub(super) fn des_key_from_7(s: &[u8; 7]) -> [u8; 8] {
    let mut key = [
        s[0] >> 1,
        ((s[0] & 0x01) << 6) | (s[1] >> 2),
        ((s[1] & 0x03) << 5) | (s[2] >> 3),
        ((s[2] & 0x07) << 4) | (s[3] >> 4),
        ((s[3] & 0x0f) << 3) | (s[4] >> 5),
        ((s[4] & 0x1f) << 2) | (s[5] >> 6),
        ((s[5] & 0x3f) << 1) | (s[6] >> 7),
        s[6] & 0x7f,
    ];
    // DES key schedule ignores the parity bit of every byte, so the plain
    // shift matches Volatility's odd-parity table lookups byte for byte.
    for byte in &mut key {
        *byte <<= 1;
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn md5_matches_rfc1321() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn hmac_md5_matches_rfc2202() {
        let key = [0x0b; 16];
        let out = hmac_md5(&key, b"Hi There").unwrap();
        assert_eq!(hex(&out), "9294727a3638bb1c13f48ef8158bfc9d");
        let out = hmac_md5(b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(hex(&out), "750c783e6ab0b503eaa86e310a5db738");
    }

    #[test]
    fn rc4_matches_reference_vectors() {
        let mut data = b"Plaintext".to_vec();
        rc4(b"Key", &mut data).unwrap();
        assert_eq!(hex(&data), "bbf316e8d940af0ad3");
        let mut data = b"Attack at dawn".to_vec();
        rc4(b"Secret", &mut data).unwrap();
        assert_eq!(hex(&data), "45a01f645fc35b383552544b9bf5");
    }

    #[test]
    fn aes128_cbc_decrypt_matches_nist_sp800_38a() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let mut data = unhex("7649abac8119b246cee98e9b12e9197d");
        aes_cbc_decrypt(&key, &iv, &mut data).unwrap();
        assert_eq!(hex(&data), "6bc1bee22e409f96e93d7e117393172a");
    }

    #[test]
    fn aes256_cbc_decrypt_matches_nist_sp800_38a() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let mut data = unhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        aes_cbc_decrypt(&key, &iv, &mut data).unwrap();
        assert_eq!(hex(&data), "6bc1bee22e409f96e93d7e117393172a");
    }

    #[test]
    fn des_ecb_decrypt_matches_fips81() {
        let key: [u8; 8] = unhex("0123456789abcdef").try_into().unwrap();
        let mut block = unhex("3fa40e8a984d4815");
        des_ecb_decrypt(&key, &mut block).unwrap();
        assert_eq!(hex(&block), "4e6f772069732074");
    }

    #[test]
    fn sid_to_key_matches_rid_layouts() {
        let (first, second) = sid_to_key(1000);
        assert_eq!(hex(&first), "e800c0000e400c00");
        assert_eq!(hex(&second), "007400600006a006");
        let (first, second) = sid_to_key(500);
        assert_eq!(hex(&first), "f40040000ea00400");
        assert_eq!(hex(&second), "007a00200006d002");
    }
}
