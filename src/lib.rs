// SHA-256 Function implemented pursuant to NIST FIPS 180-4
// which is available at https://doi.org/10.6028/NIST.FIPS.180-4

// Unit tests
#[cfg(test)]
mod tests;

// Constants to be fed into every round
const SHA256_CONST: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

// Error to be propagated if size of input into SHA-256 is greater than 2^64 bits
pub enum HashError {
    DataTooLarge
}

// Convenience struct encapsulating raw hash value that can convert hash to hex string
pub struct Sha256 {
    hash: [u32; 8]
}

impl Sha256 {
    pub fn new(inp: &[u8]) -> Result<Sha256, HashError> {
        Ok(Sha256 {
            hash: sha256(inp)?
        })
    }

    pub fn to_string(&self) -> String {
        format!("{:08x}{:08x}{:08x}{:08x}\
                 {:08x}{:08x}{:08x}{:08x}", self.hash[0],
                                            self.hash[1],
                                            self.hash[2],
                                            self.hash[3],
                                            self.hash[4],
                                            self.hash[5],
                                            self.hash[6],
                                            self.hash[7])
    }
}

fn sha256(inp: &[u8]) -> Result<[u32; 8], HashError> {
    if inp.len() > 1 << 58 {
        return Err(HashError::DataTooLarge);
    }

    let blocks = pad_data(inp);

    // Initial Hash values
    let mut hash: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    for block in blocks.iter() {
        block_hash(&mut hash, block);
    }

    Ok(hash)
}

// Pad data into 512 bit blocks.
// A '1' bit is put in the next bytes after
// the input data, and then the last two u32 values
// represent a 64 bit unsigned number which is the size
// of the input data
fn pad_data(inp: &[u8]) -> Vec<[u32; 16]> {
    let len_inp_bits = inp.len() * 8;
    
    // Calculate how many 512 bit blocks are needed for the data itself.
    // Then, if the data occupies bit 448 or greater in the last block,
    // allocate another block so that the '1' bit and the 64 bit size signature
    // fit in.
    // Lastly, if the input size is zero, then create only one block.
    let num_blocks = std::cmp::max(((len_inp_bits as f32 / 512_f32).ceil()
                          +((len_inp_bits % 512) as f32 / 448_f32).floor()) as usize, 1);

    let mut blocks = vec![[0_u32; 16]; num_blocks];

    // Keep track outside of position outside of the for loop to make inserting
    // the '1' bit easier
    let mut block_num = 0;
    let mut block_pos = 0;

    for (i, x) in inp.iter().enumerate() {
        // Could also be represented as '((i * 8) as f32 / 512_f32)'
        // However, the representation below removes the need to multiply by 8
        block_num = (i as f32 / 64_f32).floor() as usize;
        block_pos = ((i % 64) as f32 / 4_f32).floor() as usize;

        // Big endian implementation.
        // Fit four u8 values into one u32 value, going from left to right.
        blocks[block_num][block_pos] |= (*x as u32) << 24 - (i % 4 * 8);
    }

    // Determine what part of the u32 the '1' bit will fit into
    let final_u32 = inp.len() % 4;

    // If the '1' bit will be inserted into a new u32 element that
    // is not at the beginning of the array, then adjust the indices
    // accordingly.
    if final_u32 == 0 && len_inp_bits != 0 {
        if block_pos == 15 {
            block_num += 1;
            block_pos = 0;
        } else {
            block_pos += 1;
        }
    }

    // Set the most significant bit to 1, which is nearest to the end of the input
    // data, as per specification.
    blocks[block_num][block_pos] |= (128 as u32) << 24 - (final_u32 * 8);

    // Set the size signature
    blocks[num_blocks - 1][15] = len_inp_bits as u32;
    blocks[num_blocks - 1][14] = (len_inp_bits >> 32) as u32;

    blocks
}

fn block_hash(hash: &mut [u32; 8], block: &[u32; 16]) {
    // Allow for integer wrapping
    use std::num::Wrapping;

    // Message schedule
    let mut w = [Wrapping(0u32); 64];

    // The 8 working variables that are modified per round
    // TODO: Using an array is less idiomatic in respect to the NIST document,
    // but more idiomatic in respect to programming.
    let (mut a, mut b, mut c, mut d,
         mut e, mut f, mut g, mut h) = (
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7]
                                       );

    // 64 rounds to be executed per block
    for i in 0..64 {
        if i < 16 {
            w[i] = Wrapping(block[i]);
        } else {
            w[i] = Wrapping(little_sigma_one(w[i-2].0)) + w[i-7]
                 + Wrapping(little_sigma_zero(w[i-15].0)) + w[i-16];
        }
        
        let t_one = Wrapping(h) + Wrapping(big_sigma_one(e))
              + Wrapping(ch(e, f, g)) + Wrapping(SHA256_CONST[i])
              + w[i];

        let t_two = Wrapping(big_sigma_zero(a)) + Wrapping(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = (Wrapping(d) + t_one).0;
        d = c;
        c = b;
        b = a;
        a = (t_one + t_two).0;
    }

    //TODO: Get rid of all the repetition
    hash[0] = (Wrapping(hash[0]) + Wrapping(a)).0;
    hash[1] = (Wrapping(hash[1]) + Wrapping(b)).0;
    hash[2] = (Wrapping(hash[2]) + Wrapping(c)).0;
    hash[3] = (Wrapping(hash[3]) + Wrapping(d)).0;
    hash[4] = (Wrapping(hash[4]) + Wrapping(e)).0;
    hash[5] = (Wrapping(hash[5]) + Wrapping(f)).0;
    hash[6] = (Wrapping(hash[6]) + Wrapping(g)).0;
    hash[7] = (Wrapping(hash[7]) + Wrapping(h)).0;
}

// The six logical functions, 
// sharing the same name as the functions in the specification.

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma_zero(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma_one(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn little_sigma_zero(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn little_sigma_one(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
