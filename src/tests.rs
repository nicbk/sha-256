use crate::*;

fn compare_hash(inp: &[u8], other_hash: &str) {
    let hash = Sha256::new(inp);
    match hash {
        Ok(res) => assert_eq!(res.to_string(), other_hash),
        Err(err) => match err {
            HashError::DataTooLarge => panic!("Error: input size greater than 2^64 bits large.")
        }
    }
}

#[test]
fn pad_data_none() {
    let blocks = pad_data(b"");
    assert_eq!(vec![[0b10000000000000000000000000000000, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0]], blocks);
}

#[test]
fn hash_none() {
    compare_hash(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn hash_string() {
    compare_hash(b"Hello, world!", "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3");
}

#[test]
fn hash_file() {
    use std::fs::read;

    let file_bytes = read("make-4.2.1.tar.gz")
        .expect("Unable to open file");

    compare_hash(&file_bytes[..], "e40b8f018c1da64edd1cc9a6fce5fa63b2e707e404e20cad91fbae337c98a5b7");
}
