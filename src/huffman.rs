use super::*;
use byteorder::{ByteOrder, BE};
use num_traits::Signed;
use std::ops::Neg;

fn next_byte(buf: &mut &[u8]) -> u8 {
    let head = buf[0];
    *buf = &buf[1..];
    head
}

const TABS: [i16; 512] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    785, 785, 785, 785, 784, 784, 784, 784, 513, 513, 513, 513, 513, 513, 513, 513, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, -255, 1313, 1298, 1282, 785,
    785, 785, 785, 784, 784, 784, 784, 769, 769, 769, 769, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 290, 288, -255, 1313, 1298, 1282, 769, 769, 769, 769,
    529, 529, 529, 529, 529, 529, 529, 529, 528, 528, 528, 528, 528, 528, 528, 528, 512, 512, 512,
    512, 512, 512, 512, 512, 290, 288, -253, -318, -351, -367, 785, 785, 785, 785, 784, 784, 784,
    784, 769, 769, 769, 769, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 819, 818, 547, 547, 275, 275, 275, 275, 561, 560, 515, 546, 289, 274, 288, 258, -254,
    -287, 1329, 1299, 1314, 1312, 1057, 1057, 1042, 1042, 1026, 1026, 784, 784, 784, 784, 529, 529,
    529, 529, 529, 529, 529, 529, 769, 769, 769, 769, 768, 768, 768, 768, 563, 560, 306, 306, 291,
    259, -252, -413, -477, -542, 1298, -575, 1041, 1041, 784, 784, 784, 784, 769, 769, 769, 769,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, -383, -399,
    1107, 1092, 1106, 1061, 849, 849, 789, 789, 1104, 1091, 773, 773, 1076, 1075, 341, 340, 325,
    309, 834, 804, 577, 577, 532, 532, 516, 516, 832, 818, 803, 816, 561, 561, 531, 531, 515, 546,
    289, 289, 288, 258, -252, -429, -493, -559, 1057, 1057, 1042, 1042, 529, 529, 529, 529, 529,
    529, 529, 529, 784, 784, 784, 784, 769, 769, 769, 769, 512, 512, 512, 512, 512, 512, 512, 512,
    -382, 1077, -415, 1106, 1061, 1104, 849, 849, 789, 789, 1091, 1076, 1029, 1075, 834, 834, 597,
    581, 340, 340, 339, 324, 804, 833, 532, 532, 832, 772, 818, 803, 817, 787, 816, 771, 290, 290,
    290, 290, 288, 258, -253, -349, -414, -447, -463, 1329, 1299, -479, 1314, 1312, 1057, 1057,
    1042, 1042, 1026, 1026, 785, 785, 785, 785, 784, 784, 784, 784, 769, 769, 769, 769, 768, 768,
    768, 768, -319, 851, 821, -335, 836, 850, 805, 849, 341, 340, 325, 336, 533, 533, 579, 579,
    564, 564, 773, 832, 578, 548, 563, 516, 321, 276, 306, 291, 304, 259, -251, -572, -733, -830,
    -863, -879, 1041, 1041, 784, 784, 784, 784, 769, 769, 769, 769, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, -511, -527, -543, 1396, 1351, 1381, 1366,
    1395, 1335, 1380, -559, 1334, 1138, 1138, 1063, 1063, 1350, 1392, 1031, 1031, 1062, 1062, 1364,
    1363, 1120, 1120, 1333, 1348, 881, 881, 881, 881, 375, 374, 359, 373, 343, 358, 341, 325, 791,
    791, 1123, 1122, -703, 1105, 1045, -719, 865, 865, 790, 790, 774, 774,
];

const TAB32: [u8; 28] = [
    130, 162, 193, 209, 44, 28, 76, 140, 9, 9, 9, 9, 9, 9, 9, 9, 190, 254, 222, 238, 126, 94, 157,
    157, 109, 61, 173, 205,
];
const TAB33: [u8; 16] = [
    252, 236, 220, 204, 188, 172, 156, 140, 124, 108, 92, 76, 60, 44, 28, 12,
];
const TABINDEX: [i16; 32] = [
    0, 32, 64, 98, 0, 132, 180, 218, 292, 364, 426, 538, 648, 746, 0, 1126, 1460, 1460, 1460, 1460,
    1460, 1460, 1460, 1460, 1842, 1842, 1842, 1842, 1842, 1842, 1842, 1842,
];
const G_LINBITS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 6, 8, 10, 13, 4, 5, 6, 7, 8, 9, 11,
    13,
];

pub(crate) fn l3_huffman(
    dst: &mut [f32],
    bs: &mut Bs,
    gr_info: &L3GrInfo,
    scf: &[f32],
    layer3gr_limit: i32,
) {
    let mut one: f32 = 0.0;
    let mut ireg: i32 = 0;
    let mut big_val_cnt = gr_info.big_values;
    let mut sfb = gr_info.sfbtab.iter().map(|&x| u16::from(x));

    let mut bs_cache: i32 = BE::read_i32(&bs.buf[(bs.pos as usize / 8)..]);
    let mut pairs_to_decode;
    let mut np;
    let mut bs_sh = (bs.pos & 7) as i32 - 8;
    let mut bs_next_ptr = &bs.buf[(bs.pos as usize / 8) + 4..];
    let mut dst_idx = 0;

    let mut scf = scf.iter().cloned();
    while big_val_cnt > 0 {
        let tab_num = gr_info.table_select[ireg as usize];
        let mut sfb_cnt = i32::from(
            gr_info.region_count[{
                                     let _old = ireg;
                                     ireg += 1;
                                     _old
                                 } as usize],
        );
        let codebook: &[i16] = &TABS[TABINDEX[tab_num as usize] as usize..];
        let linbits = G_LINBITS[tab_num as usize];
        loop {
            np = sfb.next().unwrap() / 2;
            pairs_to_decode = if big_val_cnt > np { np } else { big_val_cnt };
            // one = *{
            //     let _old = scf;
            //     scf = scf.offset(1);
            //     _old
            // };
            one = scf.next().unwrap();
            for _ in 0..pairs_to_decode {
                let mut w: u8 = 5;
                let mut leaf = codebook[(bs_cache >> (32 - w)) as usize];
                leaf_loop1(&mut leaf, &mut w, codebook, &mut bs_sh, &mut bs_cache);
                // bs_cache = bs_cache << (leaf >> 8);
                bs_cache = bs_cache.wrapping_shl((leaf >> 8) as u32);
                bs_sh += i32::from(leaf >> 8);
                for _ in 0..2 {
                    let mut lsb = leaf & 0xf;
                    if lsb == 15 && (linbits != 0) {
                        lsb = lsb.wrapping_add(bs_cache as i16 >> (32 - linbits));
                        bs_cache <<= linbits;
                        bs_sh += i32::from(linbits);
                        fun1_obf(&mut bs_sh, &mut bs_cache, &mut bs_next_ptr);
                        dst[dst_idx] = one
                            * l3_pow_43(i32::from(lsb))
                            * if bs_cache < 0 { -1 } else { 1 } as f32;
                    } else {
                        dst[dst_idx] =
                            GPOW43[(16 + lsb)
                                       .wrapping_sub(16_i16.wrapping_mul((bs_cache >> 31) as i16))
                                       as usize]
                                * one;
                    }
                    if lsb != 0 {
                        bs_cache <<= 1;
                        bs_sh += 1;
                    }
                    // dst = dst.offset(1);
                    dst_idx += 1;
                    leaf >>= 4;
                }
                fun1_obf(&mut bs_sh, &mut bs_cache, &mut bs_next_ptr);
            }
            if !({
                big_val_cnt -= np;
                big_val_cnt
            } > 0
                && ({
                    sfb_cnt -= 1;
                    sfb_cnt
                } >= 0))
            {
                break;
            }
        }
    }
    np = 1 - big_val_cnt;
    for dst in dst[dst_idx..].chunks_mut(4) {
        let codebook_count1: &[u8] = match gr_info.count1_table {
            0 => &TAB32,
            _ => &TAB33,
        };
        let mut leaf = codebook_count1[(bs_cache >> (32 - 4)) as usize];
        if leaf & 8 == 0 {
            leaf = codebook_count1[i32::from(next_byte(&mut bs_next_ptr))
                                       .wrapping_add(bs_cache << 4 >> (32 - (leaf & 3)))
                                       as usize];
        }
        bs_cache <<= leaf & 7;
        bs_sh += i32::from(leaf & 7);
        if (bs_next_ptr.as_ptr() as isize).wrapping_sub((*bs).buf.as_ptr() as isize)
            / ::std::mem::size_of::<u8>() as isize
            * 8
            - 24
            + bs_sh as isize
            > layer3gr_limit as isize
        {
            break;
        }
        if {
            np -= 1;
            np
        } == 0
        {
            np = sfb.next().unwrap() / 2;
            if np == 0 {
                break;
            }
            // one = *{
            //     let _old = scf;
            //     scf = scf.offset(1);
            //     _old
            // };
            one = scf.next().unwrap();
        }
        if leaf & 0x80 != 0 {
            dst[0] = match_sign(&bs_cache, one);
            bs_cache <<= 1;
            bs_sh += 1;
        }
        if leaf & 0x40 != 0 {
            dst[1] = match_sign(&bs_cache, one);
            bs_cache <<= 1;
            bs_sh += 1;
        }
        if {
            np -= 1;
            np
        } == 0
        {
            np = sfb.next().unwrap() / 2;
            if np == 0 {
                break;
            }
            // one = *{
            //     let _old = scf;
            //     scf = scf.offset(1);
            //     _old
            // };
            one = scf.next().unwrap();
        }
        if leaf & 0x20 != 0 {
            dst[2] = match_sign(&bs_cache, one);
            bs_cache <<= 1;
            bs_sh += 1;
        }
        if leaf & 0x10 != 0 {
            dst[3] = match_sign(&bs_cache, one);
            bs_cache <<= 1;
            bs_sh += 1;
        }
        fun1_obf(&mut bs_sh, &mut bs_cache, &mut bs_next_ptr);
        // dst = dst.offset(4);
    }
    (*bs).pos = layer3gr_limit;
}

// TODO Determine what a good way to organize these functions would be.
// And give them real names.
fn fun1_obf(bs_sh: &mut i32, bs_cache: &mut i32, bs_next_ptr: &mut &[u8]) {
    while *bs_sh >= 0 {
        *bs_cache |= i32::from(next_byte(bs_next_ptr)) << *bs_sh;
        *bs_sh -= 8;
    }
}

fn leaf_loop1(leaf: &mut i16, w: &mut u8, codebook: &[i16], bs_sh: &mut i32, bs_cache: &mut i32) {
    while *leaf < 0 {
        *bs_cache <<= i32::from(*w);
        *bs_sh += i32::from(*w);
        *w = (*leaf & 7) as u8;
        // TODO: Check that this shouldn't be `wrapping_shr(32) - w, though that doesn't seem sensible.
        *leaf = codebook[(*bs_cache as usize)
                             .wrapping_shr(u32::from(32 - *w))
                             .wrapping_sub((*leaf >> 3) as usize)];
    }
}

fn match_sign<S, V>(sign: &S, val: V) -> V
where
    V: Neg<Output = V>,
    S: Signed,
{
    if sign.is_negative() {
        -val
    } else {
        val
    }
}
