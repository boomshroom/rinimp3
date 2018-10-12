#![cfg_attr(feature = "cargo-clippy", feature(tool_lints, rustc_private))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::excessive_precision, clippy::similar_names)
)]

extern crate arrayvec;
extern crate byteorder;
extern crate num_traits;

#[cfg(test)]
extern crate structopt;

#[cfg(test)]
extern crate minimp3;

use arrayvec::ArrayVec;
use num_traits::{One, Zero};
use std::ops::{BitAnd, Shl};

#[cfg(test)]
mod tests;

pub mod huffman;

/// Silly helper function
// pub(crate) fn fill<T>(slice: &mut [T], val: T)
// where
//     T: Copy,
// {
//     for v in slice {
//         *v = val;
//     }
// }

/// This function is here to take care of the common C
/// idiom of looping down a pointer to an array and bumping
/// the position of the pointer each iteration of the loop.
/// This works fine in Rust just by doing `s = s[1..];`
/// for immutable borrows, but with mutable ones this behavior
/// causes a double-borrow.  It SHOULD be safe though, so
/// this helper does takes a `&mut` to the slice(!) and does
/// it for us.  Panics if you try to increment past the end
/// of the slice.
pub(crate) fn increment_by_mut<T>(slice: &mut &mut [T], amount: usize) {
    let lifetime_hack = unsafe {
        let slice_ptr = slice.as_mut_ptr();
        ::std::slice::from_raw_parts_mut(slice_ptr, slice.len())
    };
    *slice = &mut lifetime_hack[amount..]
}

/// Same as `increment_by_mut()` but operates on a mutable
/// reference to an immutable slice.
///
/// This is less common than the other way around, 'cause
/// we're usually stepping down buffers that are being filled,
/// or altered, but let's follow std's convention of naming
/// const vs. mut.
pub(crate) fn increment_by<T>(slice: &mut &[T], amount: usize) {
    let lifetime_hack = unsafe {
        let slice_ptr = slice.as_ptr();
        ::std::slice::from_raw_parts(slice_ptr, slice.len())
    };
    *slice = &lifetime_hack[amount..]
}

fn test_bit<T>(v: T, shift: T) -> bool
where
    T: BitAnd<Output = T> + Shl<Output = T> + One + Zero,
{
    !(v & (T::one() << shift)).is_zero()
}

static GPOW43: [f32; 145] = [
    0.0,
    -1.0,
    -2.519_842,
    -4.326_749,
    -6.349_604,
    -8.549_88,
    -10.902_724,
    -13.390_518,
    -16.000_000,
    -18.720_754,
    -21.544_347,
    -24.463_781,
    -27.473_142,
    -30.567_351,
    -33.741_992,
    -36.993_181,
    0.0,
    1.0,
    2.519_842,
    4.326_749,
    6.349_604,
    8.549_880,
    10.902_724,
    13.390_518,
    16.000_000,
    18.720_754,
    21.544_347,
    24.463_781,
    27.473_142,
    30.567_351,
    33.741_992,
    36.993_181,
    40.317_474,
    43.711_787,
    47.173_345,
    50.699_631,
    54.288_352,
    57.937_408,
    61.644_865,
    65.408_941,
    69.227_979,
    73.100_443,
    77.024_898,
    81.000_000,
    85.024_491,
    89.097_188,
    93.216_975,
    97.382_800,
    101.593_667,
    105.848_633,
    110.146_801,
    114.487_321,
    118.869_381,
    123.292_209,
    127.755_065,
    132.257_246,
    136.798_076,
    141.376_907,
    145.993_119,
    150.646_117,
    155.335_327,
    160.060_199,
    164.820_202,
    169.614_826,
    174.443_577,
    179.305_980,
    184.201_575,
    189.129_918,
    194.090_580,
    199.083_145,
    204.107_210,
    209.162_385,
    214.248_292,
    219.364_564,
    224.510_845,
    229.686_789,
    234.892_058,
    240.126_328,
    245.389_280,
    250.680_604,
    256.000_000,
    261.347_174,
    266.721_841,
    272.123_723,
    277.552_547,
    283.008_049,
    288.489_971,
    293.998_060,
    299.532_071,
    305.091_761,
    310.676_898,
    316.287_249,
    321.922_592,
    327.582_707,
    333.267_377,
    338.976_394,
    344.709_550,
    350.466_646,
    356.247_482,
    362.051_866,
    367.879_608,
    373.730_522,
    379.604_427,
    385.501_143,
    391.420_496,
    397.362_314,
    403.326_427,
    409.312_672,
    415.320_884,
    421.350_905,
    427.402_579,
    433.475_750,
    439.570_269,
    445.685_987,
    451.822_757,
    457.980_436,
    464.158_883,
    470.357_960,
    476.577_530,
    482.817_459,
    489.077_615,
    495.357_868,
    501.658_090,
    507.978_156,
    514.317_941,
    520.677_324,
    527.056_184,
    533.454_404,
    539.871_867,
    546.308_458,
    552.764_065,
    559.238_575,
    565.731_879,
    572.243_870,
    578.774_440,
    585.323_483,
    591.890_898,
    598.476_581,
    605.080_431,
    611.702_349,
    618.342_238,
    625.000_000,
    631.675_540,
    638.368_763,
    645.079_578,
];

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Mp3Dec {
    pub mdct_overlap: [[f32; 288]; 2],
    pub qmf_state: [f32; 960],
    pub reserv: i32,
    pub free_format_bytes: i32,
    pub header: [u8; 4],
    pub reserv_buf: [u8; 511],
}

impl Mp3Dec {
    pub fn new() -> Self {
        Self {
            mdct_overlap: [[0.0; 288]; 2],
            qmf_state: [0.0; 960],
            reserv: 0,
            free_format_bytes: 0,
            header: [0; 4],
            reserv_buf: [0; 511],
        }
    }
}

impl Default for Mp3Dec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
pub struct FrameInfo {
    pub frame_bytes: i32,
    pub channels: i32,
    pub hz: i32,
    pub layer: i32,
    pub bitrate_kbps: i32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Bs<'a> {
    // pub buf: *const u8,
    pub buf: &'a [u8],
    // TODO: Should be usize
    pub pos: i32,
    // TODO: Should be usize
    pub limit: i32,
}

impl<'a> Bs<'a> {
    pub fn new(buf: &'a [u8], bytes: i32) -> Self {
        Self {
            buf,
            pos: 0,
            limit: bytes * 8,
        }
    }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct L3GrInfo {
    pub sfbtab: &'static [u8],
    pub part_23_length: u16,
    pub big_values: u16,
    pub scalefac_compress: u16,
    pub global_gain: u8,
    pub block_type: u8,
    pub mixed_block_flag: u8,
    pub n_long_sfb: u8,
    pub n_short_sfb: u8,
    pub table_select: [u8; 3],
    pub region_count: [u8; 3],
    pub subblock_gain: [u8; 3],
    pub preflag: u8,
    pub scalefac_scale: u8,
    pub count1_table: u8,
    pub scfsi: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Mp3DecScratch<'a> {
    pub bs: Bs<'a>,
    pub maindata: [u8; 2815],
    pub gr_info: [L3GrInfo; 4],
    pub grbuf: [[f32; 576]; 2],
    pub scf: [f32; 40],
    pub syn: [[f32; 64]; 33],
    pub ist_pos: [[u8; 39]; 2],
}

impl<'a> Mp3DecScratch<'a> {
    pub(crate) fn clear_grbuf(&mut self) {
        self.grbuf = [[0.0; 576]; 2];
    }
}

/*
pub struct Hdr([u8; 4]);
// TODO: Ponder unit tests for these.
impl Hdr {
    pub fn hdr_is_mono(&self) -> bool {
        // TODO: Might be nicer ways to do these bit-tests
        (self.0[3] & 0xC0) == 0xC0
    }

    pub fn hdr_is_ms_stereo(&self) -> bool {
        (self.0[3] & 0xE0) == 0x60
    }

    pub fn hdr_is_free_format(&self) -> bool {
        (self.0[2] & 0xF0) == 0
    }

    pub fn hdr_is_crc(&self) -> bool {
        // TODO: Double-check
        (self.0[1] & 1) == 0
    }

    pub fn hdr_test_padding(&self) -> bool {
        (self.0[2] & 0x2) != 0
    }

    pub fn hdr_test_mpeg1(&self) -> bool {
        (self.0[1] & 0x08) != 0
    }

    pub fn hdr_test_not_mpeg25(&self) -> bool {
        (self.0[1] & 0x10) != 0
    }

    pub fn hdr_test_i_stereo(&self) -> bool {
        (self.0[3] & 0x10) != 0
    }

    pub fn hdr_test_ms_stereo(&self) -> bool {
        (self.0[3] & 0x20) != 0
    }

    pub fn hdr_get_stereo_mode(&self) -> u8 {
        ((self.0[3] >> 6) & 3)
    }

    pub fn hdr_get_stereo_mode_ext(&self) -> u8 {
        ((self.0[3] >> 4) & 3)
    }

    pub fn hdr_get_layer(&self) -> u8 {
        ((self.0[1] >> 1) & 3)
    }

    pub fn hdr_get_bitrate(&self) -> u8 {
        (self.0[2] >> 4)
    }

    pub fn hdr_get_sample_rate(&self) -> u8 {
        ((self.0[2] >> 2) & 3)
    }

    pub fn hdr_is_frame_576(&self) -> bool {
        (self.0[1] & 14) == 2
    }

    pub fn hdr_is_layer_1(&self) -> bool {
        (self.0[1] & 6) == 6
    }

    pub fn hdr_valid(&self) -> bool {
        self.0[0] == 0xFF
            && ((self.0[1] & 0xF0) == 0xF0 || (self.0[1] & 0xFE) == 0xE2)
            && self.hdr_get_layer() != 0
            && self.hdr_get_bitrate() != 15
            && self.hdr_get_sample_rate() != 3
    }

    pub fn hdr_compare(h1: Hdr, h2: Hdr) -> bool {
        h2.hdr_valid()
            && ((h1.0[1] ^ h2.0[1]) & 0xFE) == 0
            && ((h1.0[2] ^ h2.0[2]) & 0x0C) == 0
            && !(h1.hdr_is_free_format() ^ h2.hdr_is_free_format())
    }

    pub fn hdr_bitrate_kbps(&self) -> u32 {
        let halfrate: [[[u32; 15]; 3]; 2] = [
            [
                [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80],
                [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80],
                [0, 16, 24, 28, 32, 40, 48, 56, 64, 72, 80, 88, 96, 112, 128],
            ],
            [
                [0, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160],
                [
                    0, 16, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192,
                ],
                [
                    0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224,
                ],
            ],
        ];
        2 * halfrate[self.hdr_test_mpeg1() as usize][self.hdr_get_layer() as usize - 1]
            [self.hdr_get_bitrate() as usize]
    }

    pub fn hdr_sample_rate_hz(&self) -> u32 {
        let g_hz: [u32; 3] = [44100, 48000, 32000];
        g_hz[self.hdr_get_sample_rate() as usize]
            >> (!self.hdr_test_mpeg1()) as u32
            >> (!self.hdr_test_not_mpeg25()) as u32
    }

    pub fn hdr_frame_samples(&self) -> u32 {
        if self.hdr_is_layer_1() {
            384
        } else {
            1152 >> (self.hdr_is_frame_576() as i32)
        }
    }

    pub fn hdr_frame_bytes(&self, free_format_size: u32) -> u32 {
        let mut frame_bytes =
            self.hdr_frame_samples() * self.hdr_bitrate_kbps() * 125 / self.hdr_sample_rate_hz();
        if self.hdr_is_layer_1() {
            // Slot align
            frame_bytes &= !3;
        }
        if frame_bytes != 0 {
            frame_bytes
        } else {
            free_format_size
        }
    }

    pub fn hdr_padding(&self) -> u32 {
        if self.hdr_test_padding() {
            if self.hdr_is_layer_1() {
                4
            } else {
                1
            }
        } else {
            0
        }
    }
}
*/
// TODO: All the horrible bit-tests in the `hdr_` functions
// are macros in the C version; can we translate them back to
// functions?
pub(crate) fn hdr_valid(h: &[u8]) -> bool {
    (h[0] == 0xff
        && (h[1] & 0xf0 == 0xf0 || h[1] & 0xfe == 0xe2)
        && (h[1] >> 1 & 3 != 0)
        && (h[2] >> 4 != 15)
        && (h[2] >> 2 & 3 != 3))
}

pub(crate) fn hdr_compare(h1: &[u8], h2: &[u8]) -> bool {
    (hdr_valid(h2)
        && ((h1[1] ^ h2[1]) & 0xfe == 0)
        && ((h1[2] ^ h2[2]) & 0xc == 0)
        && ((h1[2] & 0xf0 == 0) == (h2[2] & 0xf0 == 0)))
}

pub(crate) fn hdr_frame_samples(h: &[u8]) -> u32 {
    (if h[1] & 6 == 6 {
        384
    } else {
        match h[1] & 14 {
            2 => 1152 / 2,
            _ => 1152,
        }
    }) as (u32)
}

pub fn hdr_bitrate_kbps(h: &[u8]) -> u32 {
    static HALFRATE: [[[u8; 15]; 3]; 2] = [
        [
            [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80],
            [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80],
            [0, 16, 24, 28, 32, 40, 48, 56, 64, 72, 80, 88, 96, 112, 128],
        ],
        [
            [0, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160],
            [
                0, 16, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192,
            ],
            [
                0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224,
            ],
        ],
    ];
    let i1 = if (h[1] & 0x8) == 0 { 0 } else { 1 };
    let i2 = (((h[1] >> 1) & 3) - 1) as usize;
    let i3 = (h[2] >> 4) as usize;
    debug_assert!(i1 < HALFRATE.len());
    debug_assert!(i2 < HALFRATE[0].len());
    debug_assert!(i3 < HALFRATE[0][0].len());

    2 * u32::from(HALFRATE[i1][i2][i3])
}

pub fn hdr_sample_rate_hz(h: &[u8]) -> u32 {
    static G_HZ: [u32; 3] = [44100, 48000, 32000];
    G_HZ[(h[2] >> 2 & 3) as usize] >> (h[1] & 0x8 == 0) as (i32) >> (h[1] & 0x10 == 0) as (i32)
}

pub fn hdr_frame_bytes(h: &[u8], free_format_size: i32) -> i32 {
    let mut frame_bytes: i32 = hdr_frame_samples(h)
        .wrapping_mul(hdr_bitrate_kbps(h))
        .wrapping_mul(125)
        .wrapping_div(hdr_sample_rate_hz(h)) as (i32);
    if h[1] & 6 == 6 {
        frame_bytes &= !3;
    }
    match frame_bytes {
        0 => free_format_size,
        n => n,
    }
}

pub fn hdr_padding(h: &[u8]) -> i32 {
    match (h[2] & 2, h[1] & 6){
        (0, _) => 0,
        (_, 6) => 4,
        (_, _) => 1,
    }
}

pub(crate) fn mp3d_match_frame(hdr: &[u8], mp3_bytes: i32, frame_bytes: i32) -> bool {
    let mut i = 0;
    for nmatch in 0..10 {
        i += hdr_frame_bytes(&hdr[i as usize..], frame_bytes) + hdr_padding(&hdr[i as usize..]);
        if i + 4 > mp3_bytes {
            return nmatch > 0;
        }
        if !hdr_compare(hdr, &hdr[i as usize..]) {
            return false;
        }
    }
    true
}

// TODO: Make free_format_bytes and ptr_frame_bytes
// returned values instead of mut references
pub fn mp3d_find_frame(
    mut mp3: &[u8],
    mp3_bytes: i32,
    free_format_bytes: &mut i32,
    ptr_frame_bytes: &mut i32,
) -> i32 {
    let mut frame_bytes: i32;
    for i in 0..(mp3_bytes - 4) {
        if hdr_valid(mp3) {
            frame_bytes = hdr_frame_bytes(mp3, *free_format_bytes);
            let mut frame_and_padding = frame_bytes + hdr_padding(mp3);
            for k in 4.. {
                if !(frame_bytes == 0 && (k < 2304) && (i + 2 * k < mp3_bytes - 4)) {
                    break;
                }
                if hdr_compare(mp3, &mp3[k as usize..]) {
                    let fb: i32 = k - hdr_padding(mp3);
                    let nextfb: i32 = fb + hdr_padding(&mp3[k as usize..]);
                    // TODO: Double-check the hdr_compare()
                    if i + k + nextfb + 4 <= mp3_bytes
                        && hdr_compare(mp3, &mp3[(k + nextfb) as usize..])
                    {
                        frame_and_padding = k;
                        frame_bytes = fb;
                        *free_format_bytes = fb;
                    }
                }
            }
            if frame_bytes != 0
                && (i + frame_and_padding <= mp3_bytes)
                && (mp3d_match_frame(mp3, mp3_bytes - i, frame_bytes))
                || i == 0 && (frame_and_padding == mp3_bytes)
            {
                *ptr_frame_bytes = frame_and_padding;
                return i;
            }
            *free_format_bytes = 0;
        }
        mp3 = &mp3[1..];
    };
    *ptr_frame_bytes = 0;
    return (mp3_bytes - 4).max(0);
}

/// Rewritten by hand; original is on
/// <https://github.com/lieff/minimp3/blob/master/minimp3.h#L232>
pub(crate) fn get_bits(bs: &mut Bs, n: u32) -> u32 {
    let n: i32 = n as i32;

    let mut next: u32;
    let mut cache: u32 = 0;
    let s: i32 = bs.pos & 7;

    let mut shl: i32 = n + s;
    let mut p: usize = (bs.pos >> 3) as usize;
    bs.pos += n;
    if bs.pos > bs.limit {
        return 0;
    }
    next = u32::from(bs.buf[p] & (255 & s) as u8);
    p += 1;
    shl -= 8;
    while shl > 0 {
        // println!("cache, next, shl: {}, {}, {}", cache, next, shl);
        cache |= next.wrapping_shl(shl as u32);
        next = u32::from(bs.buf[p]);
        p += 1;
        shl -= 8;
    }

    // cache | ((next as u32) >> -shl)
    // Why on Eris's earth is this shifting by an almost-certainly-negative
    // number?
    // Pretty sure that's undefined behavior in C.
    // OH!  It's because shl is negative here after we've fallen out
    // of the while loop!
    // println!("cache, next, res: {}, {}, {}", cache, next, cache | ((next as u32).wrapping_shl(shl as u32)));
    cache | ((next as u32).wrapping_shr(-shl as u32))
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct L12ScaleInfo {
    pub scf: [f32; 192],
    pub total_bands: u8,
    pub stereo_bands: u8,
    pub bitalloc: [u8; 64],
    pub scfcod: [u8; 64],
}

impl Default for L12ScaleInfo {
    fn default() -> Self {
        Self {
            scf: [0.0; 192],
            total_bands: 0,
            stereo_bands: 0,
            bitalloc: [0; 64],
            scfcod: [0; 64],
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct L12SubbandAlloc {
    pub tab_offset: u8,
    pub code_tab_width: u8,
    pub band_count: u8,
}

/// TODO: This *const it returns is actually an array,
/// make it return a proper slice if possible.
pub(crate) fn l12_subband_alloc_table(
    hdr: &[u8],
    sci: &mut L12ScaleInfo,
) -> &'static [L12SubbandAlloc] {
    let mut alloc: &[L12SubbandAlloc];
    let mode = hdr[3] >> 6 & 3;
    let mut nbands: u8;
    let stereo_bands = match mode {
        3 => 0,
        1 => ((hdr[3] >> 4 & 3) << 2) + 4,
        _ => 32,
    };
    if hdr[1] & 6 == 6 {
        static G_ALLOC_L1: [L12SubbandAlloc; 1] = [L12SubbandAlloc {
            tab_offset: 76,
            code_tab_width: 4,
            band_count: 32,
        }];
        alloc = &G_ALLOC_L1[..];
        nbands = 32;
    } else if hdr[1] & 0x8 == 0 {
        static G_ALLOC_L2M2: [L12SubbandAlloc; 3] = [
            L12SubbandAlloc {
                tab_offset: 60,
                code_tab_width: 4,
                band_count: 4,
            },
            L12SubbandAlloc {
                tab_offset: 44,
                code_tab_width: 3,
                band_count: 7,
            },
            L12SubbandAlloc {
                tab_offset: 44,
                code_tab_width: 2,
                band_count: 19,
            },
        ];
        alloc = &G_ALLOC_L2M2[..];
        nbands = 30;
    } else {
        static G_ALLOC_L2M1: [L12SubbandAlloc; 4] = [
            L12SubbandAlloc {
                tab_offset: 0,
                code_tab_width: 4,
                band_count: 3,
            },
            L12SubbandAlloc {
                tab_offset: 16,
                code_tab_width: 4,
                band_count: 8,
            },
            L12SubbandAlloc {
                tab_offset: 32,
                code_tab_width: 3,
                band_count: 12,
            },
            L12SubbandAlloc {
                tab_offset: 40,
                code_tab_width: 2,
                band_count: 7,
            },
        ];
        let sample_rate_idx = hdr[2] >> 2 & 3;
        let mut kbps: u32 = hdr_bitrate_kbps(hdr) >> (mode != 3) as (i32);
        if kbps == 0 {
            kbps = 192;
        }
        alloc = &G_ALLOC_L2M1[..];
        nbands = 27;
        if kbps < 56 {
            static G_ALLOC_L2M1_LOWRATE: [L12SubbandAlloc; 2] = [
                L12SubbandAlloc {
                    tab_offset: 44,
                    code_tab_width: 4,
                    band_count: 2,
                },
                L12SubbandAlloc {
                    tab_offset: 44,
                    code_tab_width: 3,
                    band_count: 10,
                },
            ];
            alloc = &G_ALLOC_L2M1_LOWRATE[..];
            nbands = if sample_rate_idx == 2 { 12 } else { 8 };
        } else if kbps >= 96 && (sample_rate_idx != 1) {
            nbands = 30;
        }
    }
    (*sci).total_bands = nbands;
    (*sci).stereo_bands = stereo_bands.min(nbands);
    alloc
}

pub(crate) fn l12_read_scalefactors(
    bs: &mut Bs,
    mut pba: &mut [u8],
    scfcod: &mut [u8],
    bands: i32,
    mut scf: &mut [f32],
) {
    static G_DEQ_L12: [f32; 54] = [
        9.536_743_16e-07 / 3.0,
        7.569_318_07e-07 / 3.0,
        6.007_771_73e-07 / 3.0,
        9.536_743_16e-07 / 7.0,
        7.569_318_07e-07 / 7.0,
        6.007_771_73e-07 / 7.0,
        9.536_743_16e-07 / 15.0,
        7.569_318_07e-07 / 15.0,
        6.007_771_73e-07 / 15.0,
        9.536_743_16e-07 / 31.0,
        7.569_318_07e-07 / 31.0,
        6.007_771_73e-07 / 31.0,
        9.536_743_16e-07 / 63.0,
        7.569_318_07e-07 / 63.0,
        6.007_771_73e-07 / 63.0,
        9.536_743_16e-07 / 127.0,
        7.569_318_07e-07 / 127.0,
        6.007_771_73e-07 / 127.0,
        9.536_743_16e-07 / 255.0,
        7.569_318_07e-07 / 255.0,
        6.007_771_73e-07 / 255.0,
        9.536_743_16e-07 / 511.0,
        7.569_318_07e-07 / 511.0,
        6.007_771_73e-07 / 511.0,
        9.536_743_16e-07 / 1023.0,
        7.569_318_07e-07 / 1023.0,
        6.007_771_73e-07 / 1023.0,
        9.536_743_16e-07 / 2047.0,
        7.569_318_07e-07 / 2047.0,
        6.007_771_73e-07 / 2047.0,
        9.536_743_16e-07 / 4095.0,
        7.569_318_07e-07 / 4095.0,
        6.007_771_73e-07 / 4095.0,
        9.536_743_16e-07 / 8191.0,
        7.569_318_07e-07 / 8191.0,
        6.007_771_73e-07 / 8191.0,
        9.536_743_16e-07 / 16383.0,
        7.569_318_07e-07 / 16383.0,
        6.007_771_73e-07 / 16383.0,
        9.536_743_16e-07 / 32767.0,
        7.569_318_07e-07 / 32767.0,
        6.007_771_73e-07 / 32767.0,
        9.536_743_16e-07 / 65535.0,
        7.569_318_07e-07 / 65535.0,
        6.007_771_73e-07 / 65535.0,
        9.536_743_16e-07 / 3.0,
        7.569_318_07e-07 / 3.0,
        6.007_771_73e-07 / 3.0,
        9.536_743_16e-07 / 5.0,
        7.569_318_07e-07 / 5.0,
        6.007_771_73e-07 / 5.0,
        9.536_743_16e-07 / 9.0,
        7.569_318_07e-07 / 9.0,
        6.007_771_73e-07 / 9.0,
    ];
    for &item in scfcod.iter().take(bands as usize) {
        let mut s: f32 = 0.0;
        let ba: u32 = u32::from({
            let _old = pba[0];
            // pba = pba.offset(1);
            increment_by_mut(&mut pba, 1);
            _old
        });
        let mask = match ba {
            0 => 0,
            _ => 4 + (19 >> item & 3),
        };
        for m in (0..3).map(|i| 4 >> i) {
            if mask & m != 0 {
                let b: u32 = get_bits(bs, 6);
                s = G_DEQ_L12[(ba * 3 - 6 + b % 3) as usize]
                    * ((1_u32 << 21).wrapping_shr(b / 3)) as f32;
            }
            // *{
            //     let _old = scf;
            //     // scf = scf.offset(1);
            //     increment_by(scf, 1);
            //     _old
            // } = s;
            scf[0] = s;
            increment_by_mut(&mut scf, 1);
        }
    }
}

pub(crate) fn l12_read_scale_info(hdr: &[u8], bs: &mut Bs, sci: &mut L12ScaleInfo) {
    static G_BITALLOC_CODE_TAB: [u8; 92] = [
        0, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 17, 18, 3, 19, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 16, 0, 17, 18, 3, 19, 4, 5, 16, 0, 17, 18, 16, 0, 17, 18, 19, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15, 0, 17, 18, 3, 19, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 2,
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    let mut subband_alloc: &[L12SubbandAlloc] = l12_subband_alloc_table(hdr, &mut *sci);
    let mut k: u8 = 0;
    let mut ba_bits: u32 = 0;
    let mut ba_code_tab: &[u8] = &G_BITALLOC_CODE_TAB[..];
    for i in 0..(*sci).total_bands {
        let mut ba: u8;
        if i == k {
            k += subband_alloc[0].band_count;
            ba_bits = u32::from(subband_alloc[0].code_tab_width);
            ba_code_tab = &G_BITALLOC_CODE_TAB[subband_alloc[0].tab_offset as usize..];
            // subband_alloc = subband_alloc.offset(1);
            increment_by(&mut subband_alloc, 1);
        }
        let idx = get_bits(bs, ba_bits);
        ba = ba_code_tab[idx as usize];
        (*sci).bitalloc[(2 * i) as usize] = ba;
        if i < (*sci).stereo_bands {
            ba = ba_code_tab[get_bits(bs, ba_bits) as usize];
        }
        sci.bitalloc[(2 * i + 1) as usize] = match sci.stereo_bands {
            0 => 0,
            _ => ba,
        };
    }
    for i in 0..(2 * i32::from(sci.total_bands)) {
        sci.scfcod[i as usize] = match sci.bitalloc[i as usize] {
            0 => 6,
            _ if test_bit(hdr[1], 1) && test_bit(hdr[1], 2) => 2,
            _ => get_bits(bs, 2) as u8,
        };
    }
    l12_read_scalefactors(
        &mut *bs,
        &mut sci.bitalloc,
        &mut sci.scfcod,
        i32::from(sci.total_bands) * 2,
        &mut sci.scf,
    );
    for i in ((*sci).stereo_bands)..((*sci).total_bands) {
        (*sci).bitalloc[(2 * i + 1) as usize] = 0;
    }
}

pub(crate) fn l12_dequantize_granule(
    grbuf: &mut [f32],
    bs: &mut Bs,
    sci: &mut L12ScaleInfo,
    group_size: i32,
) -> i32 {
    let mut choff: i32 = 576;
    for j in 0..4 {
        let mut dst = &mut grbuf[(group_size as usize * j)..];
        for i in 0..(2 * sci.total_bands) {
            let ba = u32::from(sci.bitalloc[i as usize]);
            if ba != 0 {
                if ba < 17 {
                    let half = (1 << (ba - 1)) - 1;
                    for k in 0..group_size {
                        println!("DST: {:?}, {}, {}", dst, k, group_size);
                        // TODO: Crash happening here,
                        // dst is size 0.  Investigate.
                        dst[k as usize] = (get_bits(bs, ba) as i32 - half) as f32;
                    }
                } else {
                    let mod_: u32 = (2 << (ba - 17)) + 1;
                    let mut code = get_bits(bs, mod_.wrapping_add(2).wrapping_sub(mod_ >> 3));
                    for k in 0..group_size {
                        dst[k as usize] =
                            code.wrapping_rem(mod_).wrapping_sub(mod_.wrapping_div(2)) as f32;
                        code = code.wrapping_div(mod_);
                    }
                }
            }
            increment_by_mut(&mut dst, choff as usize);
            choff = 18 - choff;
        }
    }
    group_size * 4
}

pub(crate) fn l12_apply_scf_384(sci: &mut L12ScaleInfo, scf: &[f32], dst: &mut [f32]) {
    // memcpy(
    //     dst.offset(576)
    //         .offset(((*sci).stereo_bands as (i32) * 18) as isize)
    //         as (*mut ::std::os::raw::c_void),
    //     dst.offset(((*sci).stereo_bands as (i32) * 18) as isize) as (*const ::std::os::raw::c_void),
    //     ((((*sci).total_bands as (i32) - (*sci).stereo_bands as (i32)) * 18) as usize)
    //         .wrapping_mul(::std::mem::size_of::<f32>()),
    // );
    {
        let dst_offset = 576 + sci.stereo_bands as usize * 18;
        let src_offset = sci.stereo_bands as usize * 18;
        let len = sci.total_bands as usize - sci.stereo_bands as usize * 18;
        let (src, dst) = dst.split_at_mut(dst_offset);
        dst[..len].copy_from_slice(&src[src_offset..(src_offset + len)]);
    }
    // dst[dst_offset..(dst_offset + len)].copy_from_slice(&dst[src_offset..(src_offset+len)]);

    // for (i = 0; i < sci->total_bands; i++, dst += 18, scf += 6)
    // {
    //     for (k = 0; k < 12; k++)
    //     {
    //         dst[k + 0]   *= scf[0];
    //         dst[k + 576] *= scf[3];
    //     }
    // }
    assert!(sci.total_bands <= 32);
    let (left, right) = dst.split_at_mut(576);
    for (scf, (l, r)) in scf
        .chunks(6)
        .zip(left.chunks_mut(18).zip(right.chunks_mut(18)))
        .take(sci.total_bands as usize)
    {
        l.iter_mut().for_each(|x| *x *= scf[0]);
        r.iter_mut().for_each(|x| *x *= scf[3]);
    }
}

#[allow(non_snake_case)]
pub(crate) fn mp3d_DCT_II(grbuf: &mut [f32], n: i32) {
    static G_SEC: [f32; 24] = [
        10.190_008_16,
        0.500_603_02,
        0.502_419_29,
        3.407_608_51,
        0.505_470_93,
        0.522_498_61,
        2.057_780_98,
        0.515_447_32,
        0.566_944_06,
        1.484_164_60,
        0.531_042_58,
        0.646_821_80,
        1.169_439_91,
        0.553_103_92,
        0.788_154_60,
        0.972_568_21,
        0.582_934_98,
        1.060_677_65,
        0.839_349_63,
        0.622_504_12,
        1.722_447_16,
        0.744_536_28,
        0.674_808_32,
        5.101_148_61,
    ];
    for k in 0..n {
        // let mut t: [[f32; 8]; 4] = [[0.0; 8]; 4];
        let mut t: [f32; 32] = [0.0; 32];
        let y: &mut [f32] = &mut grbuf[k as usize..];
        {
            let mut x = t
                .chunks_mut(8)
                .take(4)
                .collect::<ArrayVec<[&mut [f32]; 4]>>();
            for (i, g_sec) in (0..8).zip(G_SEC.chunks(3)) {
                let x0: f32 = y[i * 18];
                let x1: f32 = y[(15 - i) * 18];
                let x2: f32 = y[(16 + i) * 18];
                let x3: f32 = y[(31 - i) * 18];
                let t0: f32 = x0 + x3;
                let t1: f32 = x1 + x2;
                let t2: f32 = (x1 - x2) * g_sec[0];
                let t3: f32 = (x0 - x3) * g_sec[1];
                x[0][i] = t0 + t1;
                x[1][i] = (t0 - t1) * g_sec[2];
                x[2][i] = t3 + t2;
                x[3][i] = (t3 - t2) * g_sec[2];
                // x = x.offset(1);
            }
        }
        {
            for x in t.chunks_mut(8).take(4) {
                let y = x.iter().cloned().collect::<ArrayVec<[f32; 8]>>();
                let (bot, top) = y.split_at(4);
                let z = bot
                    .iter()
                    .zip(top.iter().rev())
                    .flat_map(|(&b, &t)| ArrayVec::from([b - t, b + t]))
                    .collect::<ArrayVec<[f32; 8]>>();

                let x4 = z[1] - z[7];
                let x0 = z[1] + z[7];
                let x3 = z[3] - z[5];
                let x1 = z[3] + z[5];
                let x5 = z[6] + z[4];
                let x7 = z[2] + z[0];

                let x6 = (z[4] + z[2]) * 0.707_106_77;
                let x3 = (x3 + x4) * 0.707_106_77;
                let x5 = x5 - x7 * 0.198_912_367;
                let x7 = x7 + x5 * 0.382_683_432;
                let x5 = x5 - x7 * 0.198_912_367;
                let x9 = z[0] - x6;
                let xt = z[0] + x6;
                x[0] = x0 + x1;
                x[1] = (xt + x7) * 0.509_795_61;
                x[2] = (x4 + x3) * 0.541_196_11;
                x[3] = (x9 - x5) * 0.601_344_88;
                x[4] = (x0 - x1) * 0.707_106_77;
                x[5] = (x9 + x5) * 0.899_976_19;
                x[6] = (x4 - x3) * 1.306_563_02;
                x[7] = (xt - x7) * 2.562_915_56;
                // x = x.offset(8);
            }
        }
        // y gets overwriten just after, so why is it assigned to in a loop?
        // TODO Figure out what this is really supposed to do.
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::all))]
        {
            for i in 0..7 {
                y[(0 * 18)] = t[i];
                y[(1 * 18)] = t[2 * 8 + i] + t[3 * 8 + i] + t[3 * 8 + (i + 1)];
                y[(2 * 18)] = t[8 + i] + t[8 + (i + 1)];
                y[(3 * 18)] = t[2 * 8 + (i + 1)] + t[3 * 8 + i] + t[3 * 8 + (i + 1)];
            }
            y[0 * 18] = t[0 * 8 + 7];
            y[1 * 18] = t[2 * 8 + 7] + t[3 * 8 + 7];
            y[2 * 18] = t[1 * 8 + 7];
            y[3 * 18] = t[3 * 8 + 7];
        }
    }
}

pub(crate) fn mp3d_scale_pcm(sample: f32) -> i16 {
    if sample >= 32766.5 {
        32767
    } else if sample <= -32767.5 {
        -32768
    } else {
        let s = (sample + 0.5) as i16;
        if s < 0 {
            s - 1
        } else {
            s
        }
    }
}

pub(crate) fn mp3d_synth_pair(pcm: &mut [i16], nch: usize, mut z: &[f32]) {
    let mut a: f32;
    {
        let z = z.iter().step_by(64).collect::<ArrayVec<[_; 15]>>();
        a = z[14] - z[0] * 29.0;
        a += z[1] + z[13] * 213.0;
        a += z[12] - z[2] * 459.0;
        a += z[3] + z[11] * 2037.0;
        a += z[10] - z[4] * 5153.0;
        a += z[5] + z[9] * 6574.0;
        a += z[8] - z[6] * 37489.0;
        a += z[7] * 75038.0;
    }
    pcm[0] = mp3d_scale_pcm(a);
    increment_by(&mut z, 2);

    let coefs = [-5.0, 146.0, -45.0, -9975.0, 64019.0, 9727.0, 1567.0, 104.0];
    let a = z
        .iter()
        .step_by(2 * 64)
        .zip(coefs.iter())
        .map(|(&z, &c)| z * c)
        .sum();

    pcm[16 * nch] = mp3d_scale_pcm(a)
}

pub(crate) fn mp3d_synth(xl: &mut [f32], dstl: &mut [i16], nch: usize, lins: &mut [f32]) {
    static G_WIN: [f32; 240] = [
        -1.0, 26.0, -31.0, 208.0, 218.0, 401.0, -519.0, 2063.0, 2000.0, 4788.0, -5517.0, 7134.0,
        5959.0, 35640.0, -39336.0, 74992.0, -1.0, 24.0, -35.0, 202.0, 222.0, 347.0, -581.0, 2080.0,
        1952.0, 4425.0, -5879.0, 7640.0, 5288.0, 33791.0, -41176.0, 74856.0, -1.0, 21.0, -38.0,
        196.0, 225.0, 294.0, -645.0, 2087.0, 1893.0, 4063.0, -6237.0, 8092.0, 4561.0, 31947.0,
        -43006.0, 74630.0, -1.0, 19.0, -41.0, 190.0, 227.0, 244.0, -711.0, 2085.0, 1822.0, 3705.0,
        -6589.0, 8492.0, 3776.0, 30112.0, -44821.0, 74313.0, -1.0, 17.0, -45.0, 183.0, 228.0,
        197.0, -779.0, 2075.0, 1739.0, 3351.0, -6935.0, 8840.0, 2935.0, 28289.0, -46617.0, 73908.0,
        -1.0, 16.0, -49.0, 176.0, 228.0, 153.0, -848.0, 2057.0, 1644.0, 3004.0, -7271.0, 9139.0,
        2037.0, 26482.0, -48390.0, 73415.0, -2.0, 14.0, -53.0, 169.0, 227.0, 111.0, -919.0, 2032.0,
        1535.0, 2663.0, -7597.0, 9389.0, 1082.0, 24694.0, -50137.0, 72835.0, -2.0, 13.0, -58.0,
        161.0, 224.0, 72.0, -991.0, 2001.0, 1414.0, 2330.0, -7910.0, 9592.0, 70.0, 22929.0,
        -51853.0, 72169.0, -2.0, 11.0, -63.0, 154.0, 221.0, 36.0, -1064.0, 1962.0, 1280.0, 2006.0,
        -8209.0, 9750.0, -998.0, 21189.0, -53534.0, 71420.0, -2.0, 10.0, -68.0, 147.0, 215.0, 2.0,
        -1137.0, 1919.0, 1131.0, 1692.0, -8491.0, 9863.0, -2122.0, 19478.0, -55178.0, 70590.0,
        -3.0, 9.0, -73.0, 139.0, 208.0, -29.0, -1210.0, 1870.0, 970.0, 1388.0, -8755.0, 9935.0,
        -3300.0, 17799.0, -56778.0, 69679.0, -3.0, 8.0, -79.0, 132.0, 200.0, -57.0, -1283.0,
        1817.0, 794.0, 1095.0, -8998.0, 9966.0, -4533.0, 16155.0, -58333.0, 68692.0, -4.0, 7.0,
        -85.0, 125.0, 189.0, -83.0, -1356.0, 1759.0, 605.0, 814.0, -9219.0, 9959.0, -5818.0,
        14548.0, -59838.0, 67629.0, -4.0, 7.0, -91.0, 117.0, 177.0, -106.0, -1428.0, 1698.0, 402.0,
        545.0, -9416.0, 9916.0, -7154.0, 12980.0, -61289.0, 66494.0, -5.0, 6.0, -97.0, 111.0,
        163.0, -127.0, -1498.0, 1634.0, 185.0, 288.0, -9585.0, 9838.0, -8540.0, 11455.0, -62684.0,
        65290.0,
    ];
    // let xr = &xl[(576 * (nch - 1)) as usize..];
    let (xl, xr) = xl.split_at(576 * (nch - 1) as usize);
    // let dstr = &mut dstl[(nch - 1) as usize..];
    let dstr_offset = (nch - 1) as usize;
    {
        let zlin = &mut lins[(15 * 64)..];
        zlin[4 * 15] = xl[(18 * 16)];
        zlin[4 * 15 + 1] = xr[(18 * 16)];
        zlin[4 * 15 + 2] = xl[0];
        zlin[4 * 15 + 3] = xr[0];
        zlin[4 * 31] = xl[(1 + 18 * 16)];
        zlin[4 * 31 + 1] = xr[(1 + 18 * 16)];
        zlin[4 * 31 + 2] = xl[1];
        zlin[4 * 31 + 3] = xr[1];
    }
    mp3d_synth_pair(
        &mut dstl[dstr_offset..],
        nch as usize,
        &lins[((4 * 15) + 1)..],
    );
    mp3d_synth_pair(
        &mut dstl[dstr_offset + 32 * nch..],
        nch as usize,
        &lins[4 * 15 + 64 + 1..],
    );
    mp3d_synth_pair(dstl, nch, &lins[4 * 15..]);
    mp3d_synth_pair(&mut dstl[32 * nch..], nch, &lins[4 * 15 + 64..]);
    let mut w: &[f32] = &G_WIN[..];
    let zlin = &mut lins[(15 * 64)..];
    for i in (0..14).rev() {
        let mut a: [f32; 4] = [0.0; 4];
        let mut b: [f32; 4] = [0.0; 4];
        zlin[4 * i] = xl[18 * (31 - i)];
        zlin[4 * i + 1] = xr[18 * (31 - i)];
        zlin[4 * i + 2] = xl[1 + 18 * (31 - i)];
        zlin[4 * i + 3] = xr[1 + 18 * (31 - i)];
        zlin[4 * (i + 16)] = xl[1 + 18 * (1 + i)];
        zlin[4 * (i + 16) + 1] = xr[1 + 18 * (1 + i)];
        zlin[4 * (i - 16) + 2] = xl[18 * (1 + i)];
        zlin[4 * (i - 16) + 3] = xr[18 * (1 + i)];
        // All this nonsense with `w` is from SIMD-replacing macros;
        // I think the code we're actually getting is here:
        // https://github.com/lieff/minimp3/blob/master/minimp3.h#L1534
        // Seems simplest to just rewrite it entirely.
        // I rewrote it using macros 'cause using closures caused lifetime
        // kerfuffles.
        // TODO: Doublecheck all this.
        {
            macro_rules! load {
                ($k:expr) => {{
                    let w0: f32 = w[0];
                    increment_by(&mut w, 1);
                    let w1: f32 = w[1];
                    increment_by(&mut w, 1);
                    let vz = &zlin[4 * i - $k * 64..];
                    let vy = &zlin[4 * i - (15 - $k) * 64..];
                    (w0, w1, vz, vy)
                }};
            }
            macro_rules! S0 {
                ($k:expr) => {{
                    let (w0, w1, vz, vy) = load!($k);
                    for j in 0..4 {
                        b[j] = vz[j] * w1 + vy[j] * w0;
                        a[j] = vz[j] * w0 - vy[j] * w1;
                    }
                }};
            }
            macro_rules! S1 {
                ($k:expr) => {{
                    let (w0, w1, vz, vy) = load!($k);
                    for j in 0..4 {
                        b[j] += vz[j] * w1 + vy[j] * w0;
                        a[j] += vz[j] * w0 - vy[j] * w1;
                    }
                }};
            }
            macro_rules! S2 {
                ($k:expr) => {{
                    let (w0, w1, vz, vy) = load!($k);
                    for j in 0..4 {
                        b[j] += vz[j] * w1 + vy[j] * w0;
                        a[j] += vz[j] * w1 - vy[j] * w0;
                    }
                }};
            }
            S0!(0);
            S2!(1);
            S1!(2);
            S2!(3);
            S1!(4);
            S2!(5);
            S1!(6);
            S2!(7);
        }
        dstl[dstr_offset + (15 - i) * nch] = mp3d_scale_pcm(a[1]);
        dstl[dstr_offset + (17 + i) * nch] = mp3d_scale_pcm(b[1]);
        dstl[(15 - i) * nch] = mp3d_scale_pcm(a[0]);
        dstl[(17 + i) * nch] = mp3d_scale_pcm(b[0]);
        dstl[dstr_offset + (47 - i) * nch] = mp3d_scale_pcm(a[3]);
        dstl[dstr_offset + (49 + i) * nch] = mp3d_scale_pcm(b[3]);
        dstl[(47 - i) * nch] = mp3d_scale_pcm(a[2]);
        dstl[(49 + i) * nch] = mp3d_scale_pcm(b[2]);
    }
}

pub(crate) fn mp3d_synth_granule(
    qmf_state: &mut [f32],
    grbuf: &mut [f32],
    nbands: i32,
    nch: i32,
    pcm: &mut [i16],
    lins: &mut [f32],
) {
    for i in 0..(nch as usize) {
        // let grbuf_slice = ::std::slice::from_raw_parts_mut(grbuf, 576);
        // mp3d_DCT_II(grbuf.offset((576 * i) as isize), nbands);
        mp3d_DCT_II(&mut grbuf[..576 * i], nbands);
    }
    // memcpy(
    //     lins as (*mut ::std::os::raw::c_void),
    //     qmf_state as (*const ::std::os::raw::c_void),
    //     ::std::mem::size_of::<f32>()
    //         .wrapping_mul(15)
    //         .wrapping_mul(64),
    // );
    let len = 15 * 64;
    lins[..len].copy_from_slice(&qmf_state[..len]);
    for i in (0..nbands).step_by(2) {
        let offset = (32 * nch * i) as usize;
        mp3d_synth(
            &mut grbuf[i as usize..],
            &mut pcm[offset..],
            nch as usize,
            &mut lins[(i * 64) as usize..],
        );
    }
    if nch == 1 {
        for i in (0..(15 * 64)).step_by(2) {
            qmf_state[i as usize] = lins[(nbands * 64 + i) as usize];
        }
    } else {
        let len: i32 = 15 * 64;
        // memcpy(
        //     qmf_state as (*mut ::std::os::raw::c_void),
        //     lins.offset((nbands * 64) as isize) as (*const ::std::os::raw::c_void),
        //     ::std::mem::size_of::<f32>()
        //         .wrapping_mul(15)
        //         .wrapping_mul(64),
        // );
        qmf_state[..len as usize]
            .copy_from_slice(&lins[(nbands * 64) as usize..(nbands * 64 + len) as usize]);
    }
}

pub(crate) fn l3_read_side_info(bs: &mut Bs, mut gr: &mut [L3GrInfo], hdr: &[u8]) -> i32 {
    static G_SCF_LONG: [[u8; 23]; 8] = [
        [
            6, 6, 6, 6, 6, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 38, 46, 52, 60, 68, 58, 54, 0,
        ],
        [
            12, 12, 12, 12, 12, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 76, 90, 2, 2, 2, 2, 2, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 38, 46, 52, 60, 68, 58, 54, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 8, 10, 12, 14, 16, 18, 22, 26, 32, 38, 46, 54, 62, 70, 76, 36, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 38, 46, 52, 60, 68, 58, 54, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 8, 8, 10, 12, 16, 20, 24, 28, 34, 42, 50, 54, 76, 158, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 10, 12, 16, 18, 22, 28, 34, 40, 46, 54, 54, 192, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 8, 10, 12, 16, 20, 24, 30, 38, 46, 56, 68, 84, 102, 26, 0,
        ],
    ];
    static G_SCF_SHORT: [[u8; 40]; 8] = [
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18,
            18, 18, 24, 24, 24, 30, 30, 30, 40, 40, 40, 18, 18, 18, 0,
        ],
        [
            8, 8, 8, 8, 8, 8, 8, 8, 8, 12, 12, 12, 16, 16, 16, 20, 20, 20, 24, 24, 24, 28, 28, 28,
            36, 36, 36, 2, 2, 2, 2, 2, 2, 2, 2, 2, 26, 26, 26, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 6, 8, 8, 8, 10, 10, 10, 14, 14, 14, 18, 18,
            18, 26, 26, 26, 32, 32, 32, 42, 42, 42, 18, 18, 18, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18,
            18, 18, 24, 24, 24, 32, 32, 32, 44, 44, 44, 12, 12, 12, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18,
            18, 18, 24, 24, 24, 30, 30, 30, 40, 40, 40, 18, 18, 18, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14,
            14, 18, 18, 18, 22, 22, 22, 30, 30, 30, 56, 56, 56, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 6, 6, 6, 10, 10, 10, 12, 12, 12, 14, 14,
            14, 16, 16, 16, 20, 20, 20, 26, 26, 26, 66, 66, 66, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 6, 6, 8, 8, 8, 12, 12, 12, 16, 16, 16, 20, 20,
            20, 26, 26, 26, 34, 34, 34, 42, 42, 42, 12, 12, 12, 0,
        ],
    ];
    // TODO: These... lengths are wrong???  I jus padded them out with 0's
    static G_SCF_MIXED: [[u8; 40]; 8] = [
        [
            6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18, 18, 18, 24,
            24, 24, 30, 30, 30, 40, 40, 40, 18, 18, 18, 0, 0, 0, 0,
        ],
        [
            12, 12, 12, 4, 4, 4, 8, 8, 8, 12, 12, 12, 16, 16, 16, 20, 20, 20, 24, 24, 24, 28, 28,
            28, 36, 36, 36, 2, 2, 2, 2, 2, 2, 2, 2, 2, 26, 26, 26, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 8, 8, 10, 10, 10, 14, 14, 14, 18, 18, 18, 26,
            26, 26, 32, 32, 32, 42, 42, 42, 18, 18, 18, 0, 0, 0, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18, 18, 18, 24,
            24, 24, 32, 32, 32, 44, 44, 44, 12, 12, 12, 0, 0, 0, 0,
        ],
        [
            6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14, 18, 18, 18, 24,
            24, 24, 30, 30, 30, 40, 40, 40, 18, 18, 18, 0, 0, 0, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 4, 4, 4, 6, 6, 6, 8, 8, 8, 10, 10, 10, 12, 12, 12, 14, 14, 14,
            18, 18, 18, 22, 22, 22, 30, 30, 30, 56, 56, 56, 0, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 4, 4, 4, 6, 6, 6, 6, 6, 6, 10, 10, 10, 12, 12, 12, 14, 14, 14,
            16, 16, 16, 20, 20, 20, 26, 26, 26, 66, 66, 66, 0, 0,
        ],
        [
            4, 4, 4, 4, 4, 4, 6, 6, 4, 4, 4, 6, 6, 6, 8, 8, 8, 12, 12, 12, 16, 16, 16, 20, 20, 20,
            26, 26, 26, 34, 34, 34, 42, 42, 42, 12, 12, 12, 0, 0,
        ],
    ];
    let mut tables: u32;
    let mut scfsi: u32 = 0;
    let main_data_begin: i32;
    let mut part_23_sum: i32 = 0;
    let mut sr_idx = (hdr[2] >> 2 & 3) + ((hdr[1] >> 3 & 1) + (hdr[1] >> 4 & 1)) * 3;
    if sr_idx != 0 {
        sr_idx -= 1;
    };
    let mut gr_count: u32 = if hdr[3] & 0xc0 == 0xc0 { 1 } else { 2 };
    if test_bit(hdr[1], 3) {
        gr_count *= 2;
        main_data_begin = get_bits(bs, 9) as (i32);
        scfsi = get_bits(bs, 7 + gr_count);
    } else {
        main_data_begin = (get_bits(bs, 8 + gr_count) >> gr_count) as (i32);
    }
    for _ in 0..gr_count {
        if hdr[3] & 0xc0 == 0xc0 {
            scfsi <<= 4;
        }
        gr[0].part_23_length = get_bits(bs, 12) as (u16);
        part_23_sum += i32::from(gr[0].part_23_length);
        gr[0].big_values = get_bits(bs, 9) as (u16);
        if gr[0].big_values > 288 {
            return -1;
        }
        gr[0].global_gain = get_bits(bs, 8) as (u8);
        gr[0].scalefac_compress = get_bits(bs, if test_bit(hdr[1], 3) { 4 } else { 9 }) as (u16);
        gr[0].sfbtab = &G_SCF_LONG[sr_idx as usize];
        gr[0].n_long_sfb = 22;
        gr[0].n_short_sfb = 0;
        match get_bits(bs, 1) {
            0 => {
                gr[0].block_type = 0;
                gr[0].mixed_block_flag = 0;
                tables = get_bits(bs, 15);
                gr[0].region_count[0] = get_bits(bs, 4) as (u8);
                gr[0].region_count[1] = get_bits(bs, 3) as (u8);
                gr[0].region_count[2] = 255;
            }
            _ => {
                gr[0].block_type = get_bits(bs, 2) as (u8);
                if gr[0].block_type == 0 {
                    return -1;
                }
                gr[0].mixed_block_flag = get_bits(bs, 1) as (u8);
                gr[0].region_count[0] = 7;
                gr[0].region_count[1] = 255;
                if gr[0].block_type == 2 {
                    scfsi &= 0xf0f;
                    if gr[0].mixed_block_flag == 0 {
                        gr[0].region_count[0] = 8;
                        gr[0].sfbtab = &G_SCF_SHORT[sr_idx as usize];
                        gr[0].n_long_sfb = 0;
                        gr[0].n_short_sfb = 39;
                    } else {
                        gr[0].sfbtab = &G_SCF_MIXED[sr_idx as usize];
                        gr[0].n_long_sfb = if test_bit(hdr[1], 3) { 8 } else { 6 };
                        gr[0].n_short_sfb = 30;
                    }
                }
                tables = get_bits(bs, 10);
                tables <<= 5;
                gr[0].subblock_gain[0] = get_bits(bs, 3) as (u8);
                gr[0].subblock_gain[1] = get_bits(bs, 3) as (u8);
                gr[0].subblock_gain[2] = get_bits(bs, 3) as (u8);
            }
        }
        gr[0].table_select[0] = (tables >> 10) as (u8);
        gr[0].table_select[1] = (tables >> 5 & 31) as (u8);
        gr[0].table_select[2] = (tables & 31) as (u8);
        gr[0].preflag = if test_bit(hdr[1], 3) {
            get_bits(bs, 1) as u8
        } else if gr[0].scalefac_compress >= 500 {
            1
        } else {
            0
        };
        gr[0].scalefac_scale = get_bits(bs, 1) as (u8);
        gr[0].count1_table = get_bits(bs, 1) as (u8);
        gr[0].scfsi = (scfsi >> 12 & 15) as (u8);
        scfsi <<= 4;
        // gr = gr.offset(1);
        increment_by_mut(&mut gr, 1);
    }
    if part_23_sum + (*bs).pos > (*bs).limit + main_data_begin * 8 {
        -1
    } else {
        main_data_begin
    }
}

/// BUGGO: The lifetimes here between
/// Bs and `Mp3DecScratch` are not entirely
/// obvious; double-check.
pub(crate) fn l3_restore_reservoir<'a>(
    h: &mut Mp3Dec,
    bs: &'a mut Bs,
    s: &'a mut Mp3DecScratch<'a>,
    main_data_begin: i32,
) -> bool {
    let frame_bytes = ((bs.limit - bs.pos) / 8) as usize;
    let bytes_have = if h.reserv > main_data_begin {
        main_data_begin as usize
    } else {
        h.reserv as usize
    };
    // memcpy(
    //     (*s).maindata.as_mut_ptr() as (*mut ::std::os::raw::c_void),
    //     (*h).reserv_buf
    //         .as_mut_ptr()
    //         .offset(if 0 < (*h).reserv - main_data_begin {
    //             (*h).reserv - main_data_begin
    //         } else {
    //             0
    //         } as isize) as (*const ::std::os::raw::c_void),
    //     if (*h).reserv > main_data_begin {
    //         main_data_begin
    //     } else {
    //         (*h).reserv
    //     } as usize,
    // );
    let end = i32::max(0, h.reserv - main_data_begin) as usize;
    let len = i32::min(h.reserv, main_data_begin) as usize;
    s.maindata[..len].copy_from_slice(&h.reserv_buf[end..(end + len)]);
    // memcpy(
    //     (*s).maindata.as_mut_ptr().offset(bytes_have as isize) as (*mut ::std::os::raw::c_void),
    //     (*bs).buf.as_ptr().offset(((*bs).pos / 8) as isize) as (*const ::std::os::raw::c_void),
    //     frame_bytes as usize,
    // );
    s.maindata[bytes_have..(bytes_have + frame_bytes)]
        .copy_from_slice(&bs.buf[(bs.pos / 8) as usize..(bs.pos as usize / 8 + frame_bytes)]);
    s.bs = Bs::new(&s.maindata[..], (bytes_have + frame_bytes) as i32);
    h.reserv >= main_data_begin
}

pub(crate) fn l3_read_scalefactors(
    mut scf: &mut [u8],
    mut ist_pos: &mut [u8],
    scf_size: &[u8],
    scf_count: &[u8],
    bitbuf: &mut Bs,
    scfsi: i32,
) {
    for ((scfsi, cnt), bits) in (scfsi..)
        .step_by(2)
        .zip(scf_count.iter().map(|&x| usize::from(x)))
        .zip(scf_size.iter().map(|&x| u32::from(x)))
        .take(4)
        .take_while(|&((_, cnt), _)| cnt != 0)
    {
        if scfsi & 8 != 0 {
            // memcpy(
            //     scf as (*mut ::std::os::raw::c_void),
            //     ist_pos as (*const ::std::os::raw::c_void),
            //     cnt as usize,
            // );
            scf.copy_from_slice(&ist_pos[..cnt]);
        } else if bits == 0 {
            ist_pos
                .iter_mut()
                .zip(scf.iter_mut())
                .take(cnt)
                .for_each(|(x, y)| {
                    *x = 0;
                    *y = 0;
                })
        } else {
            let max_scf: i32 = if scfsi < 0 { (1 << bits) - 1 } else { -1 };
            for (ist, scf) in ist_pos.iter_mut().zip(scf.iter_mut()).take(cnt) {
                let s: i32 = get_bits(bitbuf, bits) as (i32);
                *ist = if s == max_scf { -1 } else { s } as (u8);
                *scf = s as (u8);
            }
        }
        // ist_pos = ist_pos.offset(cnt as isize);
        // scf = scf.offset(cnt as isize);
        increment_by_mut(&mut ist_pos, cnt);
        increment_by_mut(&mut scf, cnt);
    }
    // TODO: Clean up this horrible post-increment-y mess.
    scf[0] = {
        let _rhs = {
            let _rhs = 0;
            let _lhs = &mut scf[2];
            *_lhs = _rhs as (u8);
            *_lhs
        };
        let _lhs = &mut scf[1];
        *_lhs = _rhs;
        *_lhs
    };
}

pub(crate) fn l3_ldexp_q2(mut y: f32, mut exp_q2: i32) -> f32 {
    static G_EXPFRAC: [f32; 4] = [
        9.313_225_75e-10,
        7.831_458_14e-10,
        6.585_445_08e-10,
        5.537_677_16e-10,
    ];
    let mut e: i32;
    loop {
        e = exp_q2.min(30 * 4);
        y *= G_EXPFRAC[(e & 3) as usize] * (1 << 30 >> (e >> 2)) as f32;
        if {
            exp_q2 -= e;
            exp_q2
        } <= 0
        {
            break;
        }
    }
    y
}

pub(crate) fn l3_decode_scalefactors(
    hdr: &[u8],
    ist_pos: &mut [u8],
    bs: &mut Bs,
    gr: &L3GrInfo,
    scf: &mut [f32],
    ch: i32,
) {
    static G_SCF_PARTITIONS: [[u8; 28]; 3] = [
        [
            6, 5, 5, 5, 6, 5, 5, 5, 6, 5, 7, 3, 11, 10, 0, 0, 7, 7, 7, 0, 6, 6, 6, 3, 8, 8, 5, 0,
        ],
        [
            8, 9, 6, 12, 6, 9, 9, 9, 6, 9, 12, 6, 15, 18, 0, 0, 6, 15, 12, 0, 6, 12, 9, 6, 6, 18,
            9, 0,
        ],
        [
            9, 9, 6, 12, 9, 9, 9, 9, 9, 9, 12, 6, 18, 18, 0, 0, 12, 12, 12, 0, 12, 9, 9, 6, 15, 12,
            9, 0,
        ],
    ];
    let idx = match (gr.n_short_sfb, gr.n_long_sfb) {
        (0, 0) => 1,
        (0, _) => 0,
        (_, 0) => 2,
        (_, _) => 1,
    };
    let scf_partition = G_SCF_PARTITIONS[idx];

    let mut scf_size: [u8; 4] = [0; 4];
    let mut iscf: [u8; 40] = [0; 40];
    let scf_shift = gr.scalefac_scale + 1;
    let gain_exp: i32;
    let mut scfsi = i32::from(gr.scfsi);
    let gain: f32;
    if test_bit(hdr[1], 3) {
        static G_SCFC_DECODE: [u8; 16] = [0, 1, 2, 3, 12, 5, 6, 7, 9, 10, 11, 13, 14, 15, 18, 19];
        let part = i32::from(G_SCFC_DECODE[gr.scalefac_compress as usize]);
        scf_size[1] = {
            let _rhs = (part >> 2) as (u8);
            let _lhs = &mut scf_size[0];
            *_lhs = _rhs;
            *_lhs
        };
        scf_size[3] = {
            let _rhs = (part & 3) as (u8);
            let _lhs = &mut scf_size[2];
            *_lhs = _rhs;
            *_lhs
        };
    } else {
        static G_MOD: [u8; 24] = [
            5, 5, 4, 4, 5, 5, 4, 1, 4, 3, 1, 1, 5, 6, 6, 1, 4, 4, 4, 1, 4, 3, 1, 1,
        ];
        let mut k: i32;
        let mut modprod: i32;
        let mut sfc: i32;
        let ist: i32 = (hdr[3] & 0x10 != 0 && (ch != 0)) as (i32);
        sfc = i32::from(gr.scalefac_compress) >> ist;
        k = ist * 3 * 4;
        while sfc >= 0 {
            modprod = 1;
            for i in (0..4).rev() {
                scf_size[i as usize] = (sfc / modprod % i32::from(G_MOD[(k + i) as usize])) as (u8);
                modprod *= i32::from(G_MOD[(k + i) as usize]);
            }
            sfc -= modprod;
            k += 4;
        }
        // scf_partition = scf_partition.offset(k as isize);
        increment_by(&mut &scf_partition[..], k as usize);
        scfsi = -16;
    }
    l3_read_scalefactors(
        &mut iscf[..],
        ist_pos,
        &scf_size[..],
        &scf_partition,
        &mut *bs,
        scfsi,
    );
    if gr.n_short_sfb != 0 {
        let sh = 3 - scf_shift;
        for lhs in iscf[(gr.n_long_sfb as usize)..]
            .chunks_mut(3)
            .take(gr.n_short_sfb as usize / 3)
        {
            gr.subblock_gain
                .iter()
                .zip(lhs.iter_mut())
                .for_each(|(&rhs, lhs)| *lhs += rhs << sh);
        }
    } else if gr.preflag != 0 {
        static G_PREAMP: [u8; 10] = [1, 1, 1, 1, 2, 2, 3, 3, 3, 2];
        iscf[11..21]
            .iter_mut()
            .zip(G_PREAMP.iter())
            .for_each(|(lhs, &rhs)| *lhs += rhs);
    }
    gain_exp = i32::from(gr.global_gain) + -4 - 210 - if hdr[3] & 0xe0 == 0x60 { 2 } else { 0 };
    gain = l3_ldexp_q2(
        (1_i64 << (255 + -4 - 210 + 3)) as f32,
        ((255 + -4 - 210 + 3) & !3) - gain_exp,
    );
    scf.iter_mut()
        .zip(iscf.iter())
        .take((gr.n_long_sfb + gr.n_short_sfb) as usize)
        .for_each(|(scf, &iscf)| *scf = l3_ldexp_q2(gain, i32::from(iscf) << scf_shift))
}

pub(crate) fn l3_pow_43(mut x: i32) -> f32 {
    let frac: f32;
    let sign: i32;
    let mut mult: i32 = 256;
    if x < 129 {
        GPOW43[(16 + x) as usize]
    } else {
        if x < 1024 {
            mult = 16;
            x <<= 3;
        }
        sign = (2 * x) & 64;
        frac = ((x & 63) - sign) as f32 / ((x & !63) + sign) as f32;
        GPOW43[(16 + ((x + sign) >> 6)) as usize]
            * (1.0 + frac * (4.0 / 3.0 + frac * (2.0 / 9.0)))
            * mult as f32
    }
}

pub(crate) fn l3_midside_stereo(left: &mut [f32], n: i32) {
    println!("LEN: {}", left.len());
    // let right = &mut left[576..];
    let (left, right) = left.split_at_mut(576);
    l3_midside_stereo_b(left, right, n);
}

/// This is sometimes passed a `float[2][576]` and is sometimes,
/// it seems, passed a float array of length >= 1152.  We now
/// have two different functions for the different cases of this.
/// TODO: Can we get rid of the previous version of this?
pub(crate) fn l3_midside_stereo_b(left: &mut [f32], right: &mut [f32], n: i32) {
    for (l, r) in left.iter_mut().zip(right.iter_mut()).take(n as usize) {
        let a = *l;
        let b = *r;
        *l = a + b;
        *r = a - b;
    }
}

pub(crate) fn l3_stereo_top_band(mut right: &[f32], sfb: &[u8], nbands: i32, max_band: &mut [i32]) {
    // TODO: Clean up horrible increment operations.
    max_band[0] = {
        let _rhs = {
            let _rhs = -1;
            let _lhs = &mut max_band[2];
            *_lhs = _rhs;
            *_lhs
        };
        let _lhs = &mut max_band[1];
        *_lhs = _rhs;
        *_lhs
    };
    for (i, sfb) in sfb[..nbands as usize]
        .iter()
        .map(|&x| x as usize)
        .enumerate()
    {
        right.chunks(2).take(sfb / 2).for_each(|r| {
            if r[0] != 0.0 || r[1] != 0.0 {
                max_band[(i % 3)] = i as i32;
            }
        });
        increment_by(&mut right, sfb as usize);
    }
}

pub(crate) fn l3_intensity_stereo_band(left: &mut [f32], n: i32, kl: f32, kr: f32) {
    let (left, right) = left.split_at_mut(576);
    for (l, r) in left.iter_mut().zip(right.iter_mut()).take(n as usize) {
        *r = *l * kr;
        *l *= kl;
    }
}

pub(crate) fn l3_stereo_process(
    mut left: &mut [f32],
    ist_pos: &[u8],
    sfb: &[u8],
    hdr: &[u8],
    max_band: &mut [i32],
    mpeg2_sh: i32,
) {
    static L_PAN: [f32; 14] = [
        0.0,
        1.0,
        0.211_324_87,
        0.788_675_13,
        0.366_025_40,
        0.633_974_60,
        0.5,
        0.5,
        0.633_974_60,
        0.366_025_40,
        0.788_675_13,
        0.211_324_87,
        1.0,
        0.0,
    ];
    let max_pos: u32 = (if test_bit(hdr[1], 3) { 7 } else { 64 }) as (u32);
    for (i, &sfb) in sfb.iter().take_while(|&&x| x != 0).enumerate() {
        let ipos = u32::from(ist_pos[i]);
        if i as (i32) > max_band[i.wrapping_rem(3)] && (ipos < max_pos) {
            let mut kl: f32;
            let mut kr: f32;
            let s = if test_bit(hdr[3], 5) {
                //1.41421356
                std::f32::consts::SQRT_2
            } else {
                1.0
            };
            if test_bit(hdr[1], 3) {
                kl = L_PAN[ipos.wrapping_mul(2) as usize];
                kr = L_PAN[ipos.wrapping_mul(2).wrapping_add(1) as usize];
            } else {
                kl = 1.0;
                kr = l3_ldexp_q2(1.0, (ipos.wrapping_add(1) >> 1 << mpeg2_sh) as (i32));
                if ipos & 1 != 0 {
                    kl = kr;
                    kr = 1.0;
                }
            }
            l3_intensity_stereo_band(left, i32::from(sfb), kl * s, kr * s);
        } else if hdr[3] & 0x20 != 0 {
            l3_midside_stereo(left, i32::from(sfb));
        }
        increment_by_mut(&mut left, sfb as usize);
    }
}

pub(crate) fn l3_intensity_stereo(
    left: &mut [f32],
    ist_pos: &mut [u8],
    gr: &[L3GrInfo],
    hdr: &[u8],
) {
    let mut max_band: [i32; 3] = [0; 3];
    let n_sfb = gr[0].n_long_sfb as (usize) + gr[0].n_short_sfb as (usize);
    let max_blocks = match gr[0].n_short_sfb {
        0 => 1,
        _ => 3,
    };
    l3_stereo_top_band(&left[576..], gr[0].sfbtab, n_sfb as i32, &mut max_band);
    if gr[0].n_long_sfb != 0 {
        // TODO: This can be drastically cleaned up,
        // see https://github.com/lieff/minimp3/blob/master/minimp3.h#L926
        max_band[0] = {
            let _rhs = {
                let _rhs = if if max_band[0] < max_band[1] {
                    max_band[1]
                } else {
                    max_band[0]
                } < max_band[2]
                {
                    max_band[2]
                } else if max_band[0] < max_band[1] {
                    max_band[1]
                } else {
                    max_band[0]
                };
                let _lhs = &mut max_band[2];
                *_lhs = _rhs;
                *_lhs
            };
            let _lhs = &mut max_band[1];
            *_lhs = _rhs;
            *_lhs
        };
    }
    for (i, band) in max_band[..max_blocks]
        .iter()
        .map(|&x| x as usize)
        .enumerate()
    {
        let default_pos = if test_bit(hdr[1], 3) { 3 } else { 0 };
        let itop = n_sfb - max_blocks + i;
        let prev = itop - max_blocks;
        ist_pos[itop] = if band >= prev {
            default_pos
        } else {
            ist_pos[prev]
        };
    }
    l3_stereo_process(
        left,
        ist_pos,
        gr[0].sfbtab,
        hdr,
        &mut max_band,
        i32::from(gr[1].scalefac_compress) & 1,
    );
}

pub(crate) fn l3_reorder(mut grbuf: &mut [f32], scratch: &mut [f32], mut sfb: &[u8]) {
    // TODO: This is a horrible C-ish mess of pointers that Rust profoundly
    // dislikes, and so has been rewritten.  Needs verification and testing
    // against the original.
    while sfb[0] != 0 {
        let len = sfb[0] as usize;
        println!(
            "LEN: {}, grbuf: {}, scratch: {}",
            len,
            grbuf.len(),
            scratch.len()
        );
        {
            let gr = grbuf.chunks(len).collect::<ArrayVec<[_; 3]>>();
            for (i, s) in scratch.chunks_mut(3).enumerate().take(len) {
                s.iter_mut()
                    .zip(gr.iter().map(|g| g[i]))
                    .for_each(|(s, g)| *s = g);
            }
        }
        increment_by(&mut sfb, 3);
        increment_by_mut(&mut grbuf, 2 * len as usize);
    }
    let l = scratch.len();
    grbuf[..l].copy_from_slice(scratch);

    /*
    let mut i: usize;
    let mut len: usize;
    {
        let mut src = &&grbuf;
        let mut dst = &*scratch;
        loop {
            if !(0 != {
                len = sfb[0] as usize;
                len
            }) {
                break;
            }
            i = 0;
            loop {
                if !(i < len) {
                    break;
                }
                // TODO: Ugh, postincrement operators.
                // Double-check all this crap.
                // https://github.com/lieff/minimp3/blob/master/minimp3.h#L938
                // *{
                //     let _old = dst;
                //     dst = dst.offset(1);
                //     _old
                // } = *src.offset((0 * len) as isize);
                dst[0] = src[0 * len];
                increment_by_mut(&mut dst, 1);
                // *{
                //     let _old = dst;
                //     dst = dst.offset(1);
                //     _old
                // } = *src.offset((1 * len) as isize);
                dst[1] = src[1 * len];
                increment_by_mut(&mut dst, 1);
                // *{
                //     let _old = dst;
                //     dst = dst.offset(1);
                //     _old
                // } = *src.offset((2 * len) as isize);
    
                // src = src.offset(1);
                dst[2] = src[2 * len];
                increment_by_mut(&mut dst, 1);
                increment_by_mut(&mut src, 1);
                i = i + 1;
            }
            // sfb = sfb.offset(3);
            increment_by(&mut sfb, 3);
            // src = src.offset((2 * len) as isize);
            increment_by_mut(&mut src, 2 * len);
        }
    }
    // All this for
    // memcpy(grbuf, scratch, (dst - scratch)*sizeof(float));
    // But the implicit fucking assumption here is that dst and
    // scratch are pointers into the same array.
    // Yikes.
    // memcpy(
    //     grbuf as (*mut ::std::os::raw::c_void),
    //     scratch as (*const ::std::os::raw::c_void),
    //     (((dst as isize).wrapping_sub(scratch as isize) / ::std::mem::size_of::<f32>() as isize)
    //         as usize)
    //         .wrapping_mul(::std::mem::size_of::<f32>()),
    // );
    // let idx = (((dst as isize).wrapping_sub(scratch as isize)
    //     / ::std::mem::size_of::<f32>() as isize) as usize)
    //     .wrapping_mul(::std::mem::size_of::<f32>());
    let len = scratch.len();
    grbuf[..len].copy_from_slice(scratch);
    */
}

pub(crate) fn l3_antialias(mut grbuf: &mut [f32], nbands: i32) {
    static G_AA: [[f32; 8]; 2] = [
        [
            0.857_492_93,
            0.881_742_00,
            0.949_628_65,
            0.983_314_59,
            0.995_517_82,
            0.999_160_56,
            0.999_899_20,
            0.999_993_16,
        ],
        [
            0.514_495_76,
            0.471_731_97,
            0.313_377_45,
            0.181_913_20,
            0.094_574_19,
            0.040_965_58,
            0.014_198_56,
            0.003_699_97,
        ],
    ];
    for _ in 0..nbands {
        for i in 0..8 {
            let u: f32 = grbuf[18 + i];
            let d: f32 = grbuf[17 - i];
            grbuf[18 + i] = u * G_AA[0][i] - d * G_AA[1][i];
            grbuf[17 - i] = u * G_AA[1][i] + d * G_AA[0][i];
        }
        increment_by_mut(&mut grbuf, 18);
    }
}

/// Y is apparently an [f32;9] ?
pub(crate) fn l3_dct3_9(y: [f32; 9]) -> [f32; 9] {
    let t0 = y[0] + y[6] * 0.5;
    let s0 = y[0] - y[6];
    let t4 = (y[4] + y[2]) * 0.939_692_62;
    let t2 = (y[8] + y[2]) * 0.766_044_44;
    let s6 = (y[4] - y[8]) * 0.173_648_18;
    let s4 = y[4] + y[8] - y[2];
    let s2 = s0 - s4 * 0.5;
    let y4 = s4 + s0;
    let s8 = t0 - t2 + s6;
    let s0 = t0 - t4 + t2;
    let s4 = t0 + t4 - s6;
    let s1 = y[1];
    let s3 = y[3];
    let s5 = y[5];
    let s7 = y[7];
    let s3 = s3 * 0.866_025_40;
    let t0 = (s5 + s1) * 0.984_807_75;
    let t4 = (s5 - s7) * 0.342_020_14;
    let t2 = (s1 + s7) * 0.642_787_61;
    let s1 = (s1 - s5 - s7) * 0.866_025_40;
    let s5 = t0 - s3 - t2;
    let s7 = t4 - s3 - t0;
    let s3 = t4 + s3 - t2;
    [
        s4 - s7,
        s2 + s1,
        s0 - s3,
        s8 + s5,
        y4,
        s8 - s5,
        s0 + s3,
        s2 - s1,
        s4 + s7,
    ]
}

pub(crate) fn l3_imdct36(
    mut grbuf: &mut [f32],
    mut overlap: &mut [f32],
    window: &[f32],
    nbands: i32,
) {
    static G_TWID9: [f32; 18] = [
        0.737_277_34,
        0.793_353_34,
        0.843_391_45,
        0.887_010_83,
        0.923_879_53,
        0.953_716_95,
        0.976_296_01,
        0.991_444_86,
        0.999_048_22,
        0.675_590_21,
        0.608_761_43,
        0.537_299_61,
        0.461_748_61,
        0.382_683_43,
        0.300_705_80,
        0.216_439_61,
        0.130_526_19,
        0.043_619_38,
    ];
    for _ in 0..nbands {
        let mut co: [f32; 9] = [0.0; 9];
        let mut si: [f32; 9] = [0.0; 9];
        co[0] = -grbuf[0];
        si[0] = grbuf[17];
        for ((grbuf, si), co) in grbuf[1..]
            .chunks(4)
            .zip(si[1..].chunks_mut(2).rev())
            .zip(co[1..].chunks_mut(2))
            .take(4)
        {
            si[1] = grbuf[0] - grbuf[1];
            co[0] = grbuf[0] + grbuf[1];
            si[0] = grbuf[3] - grbuf[2];
            co[1] = -(grbuf[2] + grbuf[3]);
        }
        let mut co = l3_dct3_9(co);
        let mut si = l3_dct3_9(si);
        si[1..].iter_mut().step_by(2).for_each(|x| *x = -*x);
        for (i, j) in (0..9).zip(9..) {
            let ovl: f32 = overlap[i];
            let sum: f32 = co[i] * G_TWID9[j] + si[i] * G_TWID9[i];
            overlap[i] = co[i] * G_TWID9[i] - si[i] * G_TWID9[j];
            grbuf[i] = ovl * window[i] - sum * window[j];
            grbuf[(17 - i)] = ovl * window[j] + sum * window[i];
        }
        increment_by_mut(&mut grbuf, 18);
        increment_by_mut(&mut overlap, 9);
    }
}

pub(crate) fn l3_idct3(x0: f32, x1: f32, x2: f32, dst: &mut [f32; 3]) {
    let m1: f32 = x1 * 0.866_025_40;
    let a1: f32 = x0 - x2 * 0.5;
    dst[1] = x0 + x2;
    dst[0] = a1 + m1;
    dst[2] = a1 - m1;
}

pub(crate) fn l3_imdct12(x: &mut [f32], dst: &mut [f32], overlap: &mut [f32]) {
    static G_TWID3: [f32; 6] = [
        0.793_353_34,
        0.923_879_53,
        0.991_444_86,
        0.608_761_43,
        0.382_683_43,
        0.130_526_19,
    ];
    let mut co: [f32; 3] = [0.0; 3];
    let mut si: [f32; 3] = [0.0; 3];
    l3_idct3(-x[0], x[6] + x[3], x[12] + x[9], &mut co);
    l3_idct3(x[15], x[12] - x[9], x[6] - x[3], &mut si);
    si[1] = -si[1];
    for i in 0..3 {
        let j = 3 + i;
        let k = 5 - i;
        let ovl: f32 = overlap[i];
        let sum: f32 = co[i] * G_TWID3[j] + si[i] * G_TWID3[i];
        overlap[i] = co[i] * G_TWID3[i] - si[i] * G_TWID3[j];
        dst[i] = ovl * G_TWID3[(2 - i)] - sum * G_TWID3[k];
        dst[k] = ovl * G_TWID3[k] + sum * G_TWID3[(2 - i)];
    }
}

pub(crate) fn l3_imdct_short(mut grbuf: &mut [f32], mut overlap: &mut [f32], nbands: i32) {
    for _ in 0..nbands {
        let mut tmp: [f32; 18] = [0.0; 18];
        // memcpy(
        //     tmp.as_mut_ptr() as (*mut ::std::os::raw::c_void),
        //     grbuf.as_ptr() as (*const ::std::os::raw::c_void),
        //     ::std::mem::size_of::<[f32; 18]>(),
        // );
        tmp.copy_from_slice(&grbuf[..18]);
        // memcpy(
        //     grbuf.as_mut_ptr() as (*mut ::std::os::raw::c_void),
        //     overlap.as_ptr() as (*const ::std::os::raw::c_void),
        //     6_usize.wrapping_mul(::std::mem::size_of::<f32>()),
        // );
        grbuf.copy_from_slice(&overlap[..6]);
        l3_imdct12(&mut tmp[..], &mut grbuf[6..], &mut overlap[6..]);
        l3_imdct12(&mut tmp[1..], &mut grbuf[12..], &mut overlap[6..]);
        {
            let (a, b) = overlap.split_at_mut(6);
            l3_imdct12(&mut tmp[2..], a, b);
        }
        increment_by_mut(&mut overlap, 9);
        increment_by_mut(&mut grbuf, 18);
    }
}

pub(crate) fn l3_imdct_gr(
    mut grbuf: &mut [f32],
    mut overlap: &mut [f32],
    block_type: u32,
    n_long_bands: u32,
) {
    static G_MDCT_WINDOW: [[f32; 18]; 2] = [
        [
            0.999_048_22,
            0.991_444_86,
            0.976_296_01,
            0.953_716_95,
            0.923_879_53,
            0.887_010_83,
            0.843_391_45,
            0.793_353_34,
            0.737_277_34,
            0.043_619_38,
            0.130_526_19,
            0.216_439_61,
            0.300_705_80,
            0.382_683_43,
            0.461_748_61,
            0.537_299_61,
            0.608_761_43,
            0.675_590_21,
        ],
        [
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
            1.0,
            0.991_444_86,
            0.923_879_53,
            0.793_353_34,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.130_526_19,
            0.382_683_43,
            0.608_761_43,
        ],
    ];
    if n_long_bands != 0 {
        l3_imdct36(grbuf, overlap, &G_MDCT_WINDOW[0], n_long_bands as (i32));
        increment_by_mut(&mut grbuf, n_long_bands.wrapping_mul(18) as usize);
        increment_by_mut(&mut overlap, n_long_bands.wrapping_mul(9) as usize);
    }
    match block_type {
        2 => l3_imdct_short(grbuf, overlap, 32_u32.wrapping_sub(n_long_bands) as (i32)),
        3 => l3_imdct36(
            grbuf,
            overlap,
            &G_MDCT_WINDOW[1],
            32_u32.wrapping_sub(n_long_bands) as (i32),
        ),
        _ => l3_imdct36(
            grbuf,
            overlap,
            &G_MDCT_WINDOW[0],
            32_u32.wrapping_sub(n_long_bands) as (i32),
        ),
    }
}

/// I am rather confused about why this function uses two
/// nested loops instead of one.
pub(crate) fn l3_change_sign(mut grbuf: &mut [f32]) {
    // let mut b: i32;
    // let mut i: usize;
    // b = 0;
    // increment_by_mut(&mut grbuf, 18);
    // loop {
    //     if !(b < 32) {
    //         break;
    //     }
    //     i = 1;
    //     loop {
    //         if !(i < 18) {
    //             break;
    //         }
    //         grbuf[i] = -grbuf[i];
    //         i = i + 2;
    //     }
    //     b = b + 2;
    //     increment_by_mut(&mut grbuf, 36);
    // }
    increment_by_mut(&mut grbuf, 18);
    for _ in (0..32).skip(2) {
        grbuf.iter_mut().take(18).skip(2).for_each(|x| *x = -*x);
        if grbuf.len() >= 36 {
            increment_by_mut(&mut grbuf, 36);
        }
    }
}

pub(crate) fn l3_decode(
    h: &mut Mp3Dec,
    s: &mut Mp3DecScratch,
    mut gr_info: &mut [L3GrInfo],
    nch: i32,
) {
    for ch in 0..nch {
        let layer3gr_limit: i32 = s.bs.pos + i32::from((gr_info[ch as usize]).part_23_length);
        l3_decode_scalefactors(
            &h.header,
            &mut s.ist_pos[ch as usize],
            &mut s.bs,
            &gr_info[ch as usize],
            &mut s.scf,
            ch,
        );
        huffman::l3_huffman(
            &mut s.grbuf[ch as usize],
            &mut s.bs,
            &gr_info[ch as usize],
            &s.scf,
            layer3gr_limit,
        );
    }
    if h.header[3] & 0x10 != 0 {
        l3_intensity_stereo(&mut s.grbuf[0], &mut s.ist_pos[1], gr_info, &h.header);
    } else if h.header[3] & 0xe0 == 0x60 {
        let (left, right) = s.grbuf.split_at_mut(1);
        l3_midside_stereo_b(&mut left[0], &mut right[0], 576);
    }
    for ch in 0..nch {
        let mut aa_bands: i32 = 31;
        let n_long_bands: i32 = (match gr_info[0].mixed_block_flag {
            0 => 0,
            _ => 2,
        }) << ((h.header[2] >> 2 & 3)
            + ((h.header[1] >> 3 & 1) + (h.header[1] >> 4 & 1)) * 3
            == 2) as (i32);
        if gr_info[0].n_short_sfb != 0 {
            aa_bands = n_long_bands - 1;
            l3_reorder(
                &mut s.grbuf[ch as usize][..(n_long_bands * 18) as usize],
                &mut s.syn[0][..],
                &gr_info[0].sfbtab[gr_info[0].n_long_sfb as usize..],
            );
        }
        l3_antialias(&mut s.grbuf[ch as usize][..], aa_bands);
        l3_imdct_gr(
            &mut s.grbuf[ch as usize][..],
            &mut h.mdct_overlap[ch as usize][..],
            u32::from(gr_info[0].block_type),
            n_long_bands as (u32),
        );
        l3_change_sign(&mut s.grbuf[ch as usize]);
        // gr_info = gr_info.offset(1);
        increment_by_mut(&mut gr_info, 1);
    }
}

pub(crate) fn l3_save_reservoir(h: &mut Mp3Dec, s: &mut Mp3DecScratch) {
    let mut pos: i32 = (((*s).bs.pos + 7) as (u32)).wrapping_div(8) as (i32);
    let mut remains: i32 = ((*s).bs.limit as (u32))
        .wrapping_div(8)
        .wrapping_sub(pos as (u32)) as (i32);
    // TODO: remains can probably be way simpler.
    if remains > 511 {
        pos += remains - 511;
        remains = 511;
    }
    if remains > 0 {
        // memmove(
        //     (*h).reserv_buf.as_mut_ptr() as (*mut ::std::os::raw::c_void),
        //     (*s).maindata.as_mut_ptr().offset(pos as isize) as (*const ::std::os::raw::c_void),
        //     remains as usize,
        // );
        let slice_end = (pos + remains) as usize;
        let from_slice = &s.maindata[pos as usize..slice_end];
        h.reserv_buf[..from_slice.len()].copy_from_slice(from_slice);
    }
    h.reserv = remains;
}

/// Returns usize but I think the max length an ID3
/// tag can have is 32 bits?
pub fn mp3dec_skip_id3v2_slice(buf: &[u8]) -> usize {
    if buf.len() > 10 && buf[..3] == b"ID3\0"[..3] {
        (((buf[6] & 0x7F) as usize) << 21
            | ((buf[7] & 0x7F) as usize) << 14
            | ((buf[8] & 0x7F) as usize) << 7
            | (((buf[9] & 0x7F) as usize) + 10))
    } else {
        0
    }
}

pub fn mp3dec_decode_frame(
    dec: &mut Mp3Dec,
    mp3: &[u8],
    mut pcm: &mut [i16],
    info: &mut FrameInfo,
) -> i32 {
    let mp3_bytes = mp3.len() as i32;
    let mut i: i32 = 0;
    let mut frame_size: i32 = 0;
    let mut success = true;
    let hdr: &[u8];
    let mut bs_frame: Bs = Bs::new(&[], 0);
    let mut scratch: Mp3DecScratch = Mp3DecScratch {
        bs: bs_frame,
        maindata: [0; 2815],
        gr_info: [L3GrInfo::default(); 4],
        grbuf: [[0.0; 576]; 2],
        scf: [0.0; 40],
        syn: [[0.0; 64]; 33],
        ist_pos: [[0; 39]; 2],
    };
    if mp3_bytes > 4 && (dec.header[0] == 0xff) && hdr_compare(&dec.header, mp3) {
        frame_size = hdr_frame_bytes(mp3, dec.free_format_bytes) + hdr_padding(mp3);
        if frame_size != mp3_bytes
            && (frame_size + 4 > mp3_bytes || !hdr_compare(mp3, &mp3[frame_size as usize..]))
        {
            frame_size = 0;
        }
    }
    if frame_size == 0 {
        // memset(
        //     dec as (*mut ::std::os::raw::c_void),
        //     0,
        //     ::std::mem::size_of::<Mp3Dec>(),
        // );
        *dec = Mp3Dec::new();
        i = mp3d_find_frame(
            mp3,
            mp3_bytes,
            &mut (*dec).free_format_bytes,
            &mut frame_size,
        );
        if frame_size == 0 || i + frame_size > mp3_bytes {
            (*info).frame_bytes = i;
            return 0;
        }
    }
    hdr = &mp3[i as usize..];
    // memcpy(
    //     (*dec).header.as_mut_ptr() as (*mut ::std::os::raw::c_void),
    //     hdr.as_mut_ptr() as (*const ::std::os::raw::c_void),
    //     4,
    // );
    dec.header[0..4].copy_from_slice(&hdr[0..4]);
    info.frame_bytes = i + frame_size;
    info.channels = if hdr[3] & 0xc0 == 0xc0 { 1 } else { 2 };
    info.hz = hdr_sample_rate_hz(hdr) as (i32);
    info.layer = 4 - (i32::from(hdr[1]) >> 1 & 3);
    info.bitrate_kbps = hdr_bitrate_kbps(hdr) as (i32);
    // This was pcm.is_null()... does this work?
    if pcm.is_empty() {
        hdr_frame_samples(hdr) as (i32)
    } else {
        bs_frame = Bs::new(&hdr[4..], frame_size - 4);
        if hdr[1] & 1 == 0 {
            get_bits(&mut bs_frame, 16);
        }
        if (*info).layer == 3 {
            let main_data_begin: i32 =
                l3_read_side_info(&mut bs_frame, &mut scratch.gr_info[..], hdr);
            if main_data_begin < 0 || bs_frame.pos > bs_frame.limit {
                *dec = Mp3Dec::new();
                return 0;
            } else {
                unsafe {
                    success = l3_restore_reservoir(
                        &mut *dec,
                        &mut bs_frame,
                        // BUGGO: Defeat borrow checker
                        &mut *(&mut scratch as *mut Mp3DecScratch),
                        main_data_begin,
                    );
                }
                if success {
                    let loops = if test_bit(hdr[1], 3) { 2 } else { 1 };
                    for igr in 0..loops {
                        // memset(
                        //     scratch.grbuf[0].as_mut_ptr() as (*mut ::std::os::raw::c_void),
                        //     0,
                        //     ((576 * 2) as usize).wrapping_mul(::std::mem::size_of::<f32>()),
                        // );
                        scratch.clear_grbuf();
                        let gr_offset = (igr * (*info).channels) as usize;
                        unsafe {
                            l3_decode(
                                &mut *dec,
                                // BUGGO: Defeat borrow checker
                                &mut *(&mut scratch as *mut Mp3DecScratch),
                                &mut scratch.gr_info[gr_offset..],
                                info.channels,
                            );
                        }
                        mp3d_synth_granule(
                            &mut dec.qmf_state,
                            &mut scratch.grbuf[0][..],
                            18,
                            info.channels,
                            pcm,
                            &mut scratch.syn[0],
                        );
                        // pcm = pcm.offset((576 * (*info).channels) as isize);
                        // let pcm_lifetime_hack = unsafe {
                        //     let pcm_ptr = pcm.as_mut_ptr();
                        //     ::std::slice::from_raw_parts_mut(pcm_ptr, pcm.len())
                        // };
                        // pcm = &mut pcm_lifetime_hack[(576 * info.channels) as usize..];
                        increment_by_mut(&mut pcm, (576 * info.channels) as usize);
                    }
                }
                l3_save_reservoir(&mut *dec, &mut scratch);
            }
        } else {
            let mut sci: L12ScaleInfo = L12ScaleInfo::default();
            l12_read_scale_info(hdr, &mut bs_frame, &mut sci);
            // memset(
            //     scratch.grbuf[0].as_mut_ptr() as (*mut ::std::os::raw::c_void),
            //     0,
            //     ((576 * 2) as usize).wrapping_mul(::std::mem::size_of::<f32>()),
            // );

            scratch.clear_grbuf();
            i = 0;
            for igr in 0..3 {
                if 12 == {
                    println!(
                        "ARGS: {:?}, {:?}, {}",
                        &mut scratch.grbuf[0][i as usize..].len(),
                        &mut sci.total_bands,
                        (*info).layer | 1,
                    );
                    i = i + l12_dequantize_granule(
                        &mut scratch.grbuf[0][i as usize..],
                        &mut bs_frame,
                        &mut sci,
                        (*info).layer | 1,
                    );
                    i
                } {
                    i = 0;
                    // BUGGO Gotta defeat the borrow checker here;
                    // borrowing both sci and sci.scf
                    unsafe {
                        l12_apply_scf_384(
                            &mut *(&mut sci as *mut L12ScaleInfo),
                            &sci.scf[igr as usize..],
                            &mut scratch.grbuf[0],
                        );
                    }
                    mp3d_synth_granule(
                        &mut dec.qmf_state,
                        &mut scratch.grbuf[0][..],
                        12,
                        (*info).channels,
                        pcm,
                        &mut scratch.syn[0],
                    );
                    // memset(
                    //     scratch.grbuf[0].as_mut_ptr() as (*mut ::std::os::raw::c_void),
                    //     0,
                    //     ((576 * 2) as usize).wrapping_mul(::std::mem::size_of::<f32>()),
                    // );
                    scratch.clear_grbuf();
                    // pcm = pcm.offset((384 * (*info).channels) as isize);
                    // BUGGO: Borrow checker defeat here.
                    // let pcm_lifetime_hack = unsafe {
                    //     let pcm_ptr = pcm.as_mut_ptr();
                    //     ::std::slice::from_raw_parts_mut(pcm_ptr, pcm.len())
                    // };
                    // pcm = &mut pcm_lifetime_hack[(384 * info.channels) as usize..]
                    increment_by_mut(&mut pcm, (384 * info.channels) as usize);
                }
                if bs_frame.pos > bs_frame.limit {
                    *dec = Mp3Dec::new();
                    return 0;
                }
            }
        }
        (success as (u32)).wrapping_mul(hdr_frame_samples(&dec.header)) as (i32)
    }
}
