const M: usize = 2_usize.pow(16);

pub fn weak_checksums(bytes: &Vec<u8>, s: usize) -> Vec<u32> {
    let mut block_checksums = Vec::<u32>::new();

    // Get the weak checksums for each block
    let mut k = 0;
    let mut l = s - 1;
    while l < bytes.len() {
        block_checksums.push(
            weak_block_checksum(
                bytes,
                k,
                l,
            )
        );

        k = l + 1;
        l += s;
    }

    // Get the last block when the block size is less than S
    println!("{k}, {l}");
    if k < bytes.len() {
        block_checksums.push(
            weak_block_checksum(
                bytes, 
                k, 
                bytes.len() - 1,
            )
        );
    }

    block_checksums
}

// Calculate beta's weak block checksums
fn weak_block_checksum(bytes: &[u8], k: usize, l: usize) -> u32 {
    let mut a: u64 = 0;
    let mut b: u64 = 0;

    for i in k..=l {
        a += bytes[i] as u64;
        b += (l - i + 1) as u64 * bytes[i] as u64;
    }

    a %= M as u64;
    a %= M as u64;

    a as u32 | ((b as u32) << 16)
}



#[cfg(test)]
mod tests {
    use super::*;

    // Independent reference implementation using global indices.
    // Both k and l are inclusive indices into the original byte slice.
    fn reference_checksum(bytes: &[u8], k: usize, l: usize) -> u32 {
        assert!(k <= l);
        assert!(l < bytes.len());

        let mut a: u64 = 0;
        let mut b: u64 = 0;

        for i in k..=l {
            a += bytes[i] as u64;
            b += (l - i + 1) as u64 * bytes[i] as u64;
        }

        a %= 65536;
        b %= 65536;

        ((b as u32) << 16) | a as u32
    }

    // Calculate all expected block checksums using global indices.
    fn reference_file_checksums(bytes: &[u8], s: usize) -> Vec<u32> {
        assert!(s > 0);

        let mut checksums = Vec::new();
        let mut k = 0;

        while k < bytes.len() {
            let l = k.saturating_add(s).min(bytes.len()) - 1;
            checksums.push(reference_checksum(bytes, k, l));
            k = l + 1;
        }

        checksums
    }

    // Tests for weak_block_checksum()

    #[test]
    fn test_single_byte_checksum() {
        let bytes = vec![255];

        assert_eq!(
            weak_block_checksum(&bytes, 0, 0),
            0x00FF00FF
        );
    }

    #[test]
    fn test_known_block_checksum() {
        let bytes = vec![1, 2, 3, 4];

        // a = 10
        // b = 4*1 + 3*2 + 2*3 + 1*4 = 20
        assert_eq!(
            weak_block_checksum(&bytes, 0, 3),
            (20 << 16) | 10
        );
    }

    #[test]
    fn test_nonzero_start_index() {
        let bytes = vec![99, 10, 20, 30, 99];

        // Global indices: k = 1, l = 3
        // a = 60
        // b = 3*10 + 2*20 + 1*30 = 100
        assert_eq!(
            weak_block_checksum(&bytes, 1, 3),
            (100 << 16) | 60
        );
    }

    #[test]
    fn test_checksum_overflow() {
        let bytes = vec![255; 300];

        assert_eq!(
            weak_block_checksum(&bytes, 0, 299),
            reference_checksum(&bytes, 0, 299)
        );
    }

    #[test]
    fn test_zero_bytes() {
        let bytes = vec![0; 16];

        assert_eq!(
            weak_block_checksum(&bytes, 0, 15),
            0
        );
    }

    // Tests for weak_checksums()

    #[test]
    fn test_empty_file() {
        let bytes = vec![];

        assert!(weak_checksums(&bytes, 4).is_empty());
    }

    #[test]
    fn test_exactly_one_block() {
        let bytes = vec![1, 2, 3, 4];

        let expected = reference_file_checksums(&bytes, 4);

        assert_eq!(weak_checksums(&bytes, 4), expected);
    }

    #[test]
    fn test_multiple_full_blocks() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Expected global ranges: [0,3], [4,7]
        let expected = reference_file_checksums(&bytes, 4);

        assert_eq!(weak_checksums(&bytes, 4), expected);
    }

    #[test]
    fn test_partial_final_block() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Expected global ranges: [0,3], [4,7], [8,9]
        let expected = reference_file_checksums(&bytes, 4);

        assert_eq!(weak_checksums(&bytes, 4), expected);
    }

    #[test]
    fn test_block_size_larger_than_file() {
        let bytes = vec![10, 20, 30];

        // Expected global range: [0,2]
        let expected = reference_file_checksums(&bytes, 8);

        assert_eq!(weak_checksums(&bytes, 8), expected);
    }

    #[test]
    fn test_block_size_one() {
        let bytes = vec![10, 20, 30];

        // Expected global ranges: [0,0], [1,1], [2,2]
        let expected = reference_file_checksums(&bytes, 1);

        assert_eq!(weak_checksums(&bytes, 1), expected);
    }
}
