use md5::{Md5, Digest};
use std::fs::File;
use std::io::{Result, BufReader, ErrorKind, Read};

const M: usize = 2_usize.pow(16);


pub struct BlockSignature {
    pub weak: u32,
    pub strong: Vec<u8>,
}

fn read_block<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total_read = 0;

    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break,     // EOF
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(total_read)
}

pub fn gen_beta_checksums(path: &str, s: usize) -> Result<Vec<BlockSignature>> {
    let mut signatures = Vec::<BlockSignature>::new();

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; s];

    loop {
        let bytes_read = read_block(&mut reader, &mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // Slice for the final block which is unlikely to fully occupy buffer
        let block = &buffer[..bytes_read];

        // Generate the block signatures (weak + strong hashes) and add 
        // the requisite struct to the vector
        let weak = weak_block_checksum(block);
        let strong = strong_block_checksum(block);
        signatures.push(BlockSignature { weak, strong });
    }

    Ok(signatures)
}

// Calculate the weak checksum for a block
fn weak_block_checksum(bytes: &[u8]) -> u32 {
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let k = 0;
    let l = bytes.len() - 1;    // Panics on empty slice; use caution!

    for i in k..=l {
        a += bytes[i] as u64;
        b += (l - i + 1) as u64 * bytes[i] as u64;
    }

    a %= M as u64;
    b %= M as u64;

    a as u32 | ((b as u32) << 16)
}

// Calculate the strong checksum (MD5) for a block
fn strong_block_checksum(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();

    hasher.update(&bytes);

    hasher.finalize().to_vec()
}


#[cfg(test)]
mod weak_checksum_tests {
    use super::*;

    // Independent reference implementation using block-local
    // indices. Summing prefixes is equivalent to the weighted
    // sum used in the rsync paper.
    fn reference_weak_block_checksum(bytes: &[u8]) -> u32 {
        assert!(!bytes.is_empty());

        let a: u64 = bytes.iter()
            .map(|&byte| u64::from(byte))
            .sum();

        let b: u64 = (1..=bytes.len())
            .map(|end| {
                bytes[..end]
                    .iter()
                    .map(|&byte| u64::from(byte))
                    .sum::<u64>()
            })
            .sum();

        (((b % 65536) as u32) << 16)
            | ((a % 65536) as u32)
    }

    #[test]
    fn test_weak_single_byte_block() {
        assert_eq!(
            weak_block_checksum(&[255]),
            0x00FF00FF
        );
    }

    #[test]
    fn test_weak_known_four_byte_block() {
        // a = 10
        // b = 4*1 + 3*2 + 2*3 + 1*4 = 20
        assert_eq!(
            weak_block_checksum(&[1, 2, 3, 4]),
            (20 << 16) | 10
        );
    }

    #[test]
    fn test_weak_subslice_uses_local_distances() {
        let file_bytes = [99, 10, 20, 30, 99];

        // Only [10, 20, 30] should be checksummed.
        // a = 60, b = 100
        assert_eq!(
            weak_block_checksum(&file_bytes[1..4]),
            (100 << 16) | 60
        );

        assert_eq!(
            weak_block_checksum(&[10, 20, 30]),
            (100 << 16) | 60
        );
    }

    #[test]
    fn test_weak_zero_filled_block() {
        assert_eq!(
            weak_block_checksum(&[0; 16]),
            0
        );
    }

    #[test]
    fn test_weak_byte_order_affects_weighted_sum() {
        let forward = weak_block_checksum(&[1, 2, 3]);
        let reverse = weak_block_checksum(&[3, 2, 1]);

        // Same a, different b.
        assert_eq!(forward & 0xFFFF, reverse & 0xFFFF);
        assert_ne!(forward, reverse);
    }

    #[test]
    fn test_weak_modulo_with_large_block() {
        // Both sums exceed 16 bits.
        let bytes = vec![255; 400];

        assert_eq!(
            weak_block_checksum(&bytes),
            reference_weak_block_checksum(&bytes)
        );
    }

    #[test]
    fn test_weak_varied_binary_block() {
        let bytes = [0, 255, 128, 1, 0, 42, 255];

        assert_eq!(
            weak_block_checksum(&bytes),
            reference_weak_block_checksum(&bytes)
        );
    }
}

#[cfg(test)]
mod strong_checksum_tests {
    use super::*;

    fn strong_digest_to_hex(digest: &[u8]) -> String {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn test_strong_known_abc_block() {
        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(b"abc")
            ),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn test_strong_known_def_block() {
        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(b"def")
            ),
            "4ed9407630eb1000c0f6b63842defa7d"
        );
    }

    #[test]
    fn test_strong_empty_block() {
        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(b"")
            ),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn test_strong_single_byte_block() {
        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(b"a")
            ),
            "0cc175b9c0f1b6a831c399e269772661"
        );
    }

    #[test]
    fn test_strong_subslice_only_hashes_selected_bytes() {
        let file_bytes = b"xxabcyy";

        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(&file_bytes[2..5])
            ),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn test_strong_binary_block() {
        let bytes = [0, 255, 128, 1, 0, 42, 255];

        assert_eq!(
            strong_digest_to_hex(
                &strong_block_checksum(&bytes)
            ),
            "9d241339bef774bc3aac49653487223e"
        );
    }

    #[test]
    fn test_strong_repeatable_between_calls() {
        let first = strong_block_checksum(b"abc");
        let second = strong_block_checksum(b"def");
        let third = strong_block_checksum(b"abc");

        assert_ne!(first, second);
        assert_eq!(first, third);
    }

    #[test]
    fn test_strong_digest_length_is_16_bytes() {
        for block in [
            &b""[..],
            &b"a"[..],
            &b"abc"[..],
            &b"a longer block of bytes"[..],
        ] {
            assert_eq!(
                strong_block_checksum(block).len(),
                16
            );
        }
    }
}
