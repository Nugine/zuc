#![allow(unused_imports, unused_variables)]

use std::ops::BitXor;
use bytemuck::cast_slice;
use crate::ZUC128;

fn encryption_xor(ck: u128, iv: u128, length: u32, ibs: &[u8]) -> Vec<u8> {
    let l = (length + 31) / 32;

    let ck = ck.to_be_bytes();
    let iv = iv.to_ne_bytes();

    println!("CK: ");
    print_arr_u8(&ck);
    println!("IV: ");
    print_arr_u8(&iv);

    let mut zuc = ZUC128::new(&ck, &iv);
    let mut keys = (0..l)
                            .flat_map(|_| {
                                let z = zuc.generate().to_be();
                                [ z as u8, (z >> 8)  as u8, (z >> 16) as u8, (z >> 24) as u8]
                            })
                            .collect::<Vec<u8>>();

    keys.truncate(length as usize / 8 + 1);
    if length % 8 != 0 {
        keys[length as usize / 8] &= 0xFF << (8 - length % 8);
    }
    keys.extend(std::iter::repeat(0x0).take(ibs.len() - keys.len()));

    let mut res = ibs.to_vec();
    res.iter_mut().zip(keys.iter()).for_each(|(ib, k)| { *ib ^= k; });
    println!("RES: ");
    print_vec_u8(&res);
    res
}

fn eea3_128(count: u32, bearer: u32, direction: u32, ck: u128, length: u32, ibs: &[u8]) -> Vec<u8> {
    // init
    let bearer = bearer as u8 & ((1 << 6) - 1);
    let direction = direction as u8 & 0x1;

    let mut iv = [0_u8; 16];
    iv[0] = (count >> 24) as u8;
    iv[1] = (count >> 16) as u8;
    iv[2] = (count >> 8) as u8;
    iv[3] = count as u8;
    iv[4] = bearer << 3 | direction << 2 | 00;
    iv[5..=7].fill(0x0);
    let tmp = &iv[0..8].to_vec();
    iv[8..16].copy_from_slice(&tmp);

    println!("IV: "); // CHECK
    print_arr_u8(&iv);

    encryption_xor(ck, u128::from_ne_bytes(iv), length, ibs)
}


fn print_vec_u8(vec: &Vec<u8>) {
    vec.iter().for_each(|x| print!("{:02x} ", x));
    println!()
}
fn print_arr_u8(vec: &[u8]) {
    vec.iter().for_each(|x| print!("{:02x} ", x));
    println!()
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use bytemuck::{cast_slice, Pod};
    use crate::eea3_128::{eea3_128, print_arr_u8, print_vec_u8};
    use crate::ZUC128;

    #[test]
    fn test_1() { // 3GPP LTE Example 1
        let ck: u128 = 0x17_3d_14_ba_50_03_73_1d_7a_60_04_94_70_f0_0a_29;
        let count: u32 = 0x66035492;
        let bearer: u32 = 0xf;
        let direction: u32 = 0;
        let length: u32 = 0xc1;
        let ibs: [u8; 28] = [
            0x6c, 0xf6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xab, 0x0c, 0x97, 0x52, 0xfa, 0x6f, 0x90, 0x25,
            0xfe, 0x0b, 0xd6, 0x75, 0xd9, 0x00, 0x58, 0x75, 0xb2, 0x00, 0x00, 0x00, 0x00,
        ];
        let obs: [u8; 28] = [
            0xa6, 0xc8, 0x5f, 0xc6, 0x6a, 0xfb, 0x85, 0x33, 0xaa, 0xfc, 0x25, 0x18, 0xdf, 0xe7, 0x84,
            0x94, 0x0e, 0xe1, 0xe4, 0xb0, 0x30, 0x23, 0x8c, 0xc8, 0x00, 0x00, 0x00, 0x00
        ];

        assert_eq!(
            eea3_128(count, bearer, direction, ck, length, &ibs),
            cast_slice(&obs[..])
        )
    }
}