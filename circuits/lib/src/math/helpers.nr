// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Helper functions for circuit construction and cryptographic operations.
use crate::math::polynomial::Polynomial;

/// Inline expression that computes packed_len at the type level.
///
/// Noir does not support comptime function calls in type positions, so
/// the packed-length formula must be written inline wherever a fixed array
/// size is needed:
///
///   PACKED_LEN(A, L, BIT) =
///     L * ((A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1)
///          / (254 / (((BIT + 3) / 4) * 4 + 4)))
///
/// This is equivalent to:
///   nibble_bits = ceil(BIT / 4) * 4
///   group = floor(254 / (nibble_bits + 4))
///   num_chunks = ceil(A / group)
///   result = L * num_chunks
///
/// The comptime function below is still useful for readability in
/// non-type contexts (e.g., assertions, debug).
pub comptime fn packed_len<let A: u32, let L: u32, let BIT: u32>() -> u32 {
    let nibble_bits = ((BIT + 3) / 4) * 4;
    let group = 254 / (nibble_bits + 4);
    let num_chunks = (A + group - 1) / group;
    L * num_chunks
}

/// Compute hex-aligned packing parameters for a given `BIT`.
///
/// # Purpose
/// Returns `(nibble_bits, group)` for use by pack/flatten so layout stays consistent.
/// - `nibble_bits`: ceil (`BIT`) to the next multiple of 4 (nibble alignment).
///   - Examples: `BIT = 7 -> 8`, `BIT = 8 -> 8`, `BIT = 9 -> 12`, `BIT = 10 -> 12`, `BIT = 11 -> 12`,
///     `BIT=16 -> 16`, `BIT = 17 -> 20`.
/// - `group`: max number of encoded limbs that fit in one BN254 field element,
///            when each limb uses an extra 4 bits (see below).
///
/// # Rationale
/// - We align to nibbles so powers of two are hex-friendly and deterministic.
/// - We reserve one extra nibble (4 bits) per stored value to lift signed
///   coefficients into the non-negative range (e.g., store `v + 2^nibble_bits`),
///   which implies a radix of `2^(nibble_bits + 4)`.
///
/// # Safety
/// - Asserts `nibble_bits + 4 <= 254` to avoid mod-p wrap on BN254.
/// - Ensures at least one limb fits: `group >= 1`.
fn packing_layout<let BIT: u32>() -> (u32, u32) {
    // Ceil BIT up to the next multiple of 4 (nibble alignment).
    let nibble_bits = ((BIT + 3) / 4) * 4;

    // Each stored limb uses an extra nibble because negative coefficients
    // will be shifted to positive, so radix = 2^(nibble_bits+4).
    assert(nibble_bits + 4 <= 254);

    // Maximum limbs that fit in one BN254 element without wrap.
    let group = 254 / (nibble_bits + 4);
    assert(group >= 1);
    (nibble_bits, group)
}

/// Pack `A` values into a fixed-size array of carriers using the shared hex-aligned layout.
///
/// Computes `(nibble_bits, group)` via `packing_layout::<BIT>()`.
/// Encodes each value as a limb `digit = v + 2^nibble_bits` and concatenates
/// limbs in base `radix = 2^(nibble_bits + 4)` (one extra nibble of headroom).
/// Packs up to `group` limbs per carrier (fits within BN254 254-bit capacity).
/// Pads the last, partial carrier with `digit = 2^nibble_bits` to keep a stable layout.
///
/// The array length is `PACKED_LEN(A, 1, BIT)` = `ceil(A / group)`.
///
/// ## Generics
/// - `A`: number of input values.
/// - `BIT`: per-value bit bound; rounded up to `nibble_bits` by `packing_layout`.
pub fn pack_arr<let A: u32, let BIT: u32>(
    values: [Field; A],
) -> [Field; (A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1) / (254 / (((BIT + 3) / 4) * 4 + 4))] {
    let (nibble_bits, group) = packing_layout::<BIT>();
    let base = 2.pow_32(nibble_bits as Field);
    let radix = 2.pow_32((nibble_bits + 4) as Field);
    let num_chunks = (A + group - 1) / group;

    let mut out = [0; (A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1) / (254 / (((BIT + 3) / 4) * 4 + 4))];

    for chunk in 0..num_chunks {
        let remain = A - (chunk * group);
        let take = if remain < group { remain } else { group };

        let mut acc = 0;
        for i in 0..take {
            let v = values[chunk * group + i];
            acc = acc * radix + (v + base);
        }
        for _ in 0..(group - take) {
            acc = acc * radix + base;
        }

        out[chunk] = acc;
    }
    out
}

/// Flatten `L` polynomials into a fixed-size array of packed `Field` carriers.
///
/// For each CRT limb `j` in `0..L`, packs the coefficients of `poly[j]`
/// with `pack_arr::<A, BIT>` and writes the resulting carriers into the output.
/// The array length is `PACKED_LEN(A, L, BIT)`.
///
/// ## Generics
/// - `A`: polynomial degree (number of coefficients per polynomial).
/// - `L`: number of CRT bases (polynomials).
/// - `BIT`: per-coefficient bit bound used by the packing layout (compile-time).
pub fn flatten_arr<let A: u32, let L: u32, let BIT: u32>(
    poly: [Polynomial<A>; L],
) -> [Field; L * ((A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1) / (254 / (((BIT + 3) / 4) * 4 + 4)))] {
    let num_chunks = (A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1) / (254 / (((BIT + 3) / 4) * 4 + 4));

    let mut out = [0; L * ((A + 254 / (((BIT + 3) / 4) * 4 + 4) - 1) / (254 / (((BIT + 3) / 4) * 4 + 4)))];

    for j in 0..L {
        let packed = pack_arr::<A, BIT>(poly[j].coefficients);
        for i in 0..num_chunks {
            out[j * num_chunks + i] = packed[i];
        }
    }
    out
}

#[test]
fn test_pack_arr() {
    // Test pack_arr function directly with small values
    let values = [1, 2, 3, 4];
    let packed = pack_arr::<4, 4>(values);

    // With BIT=4, nibble_bits=4, group = floor(254/(4+4)) = 31
    // So all 4 values fit in one carrier
    assert(packed[0] != 0);

    // Test with negative values
    let values_neg = [-1, 2, -3, 4];
    let packed_neg = pack_arr::<4, 4>(values_neg);
    assert(packed_neg[0] != 0);
}

#[test]
fn test_pack_arr_single_value() {
    // Test packing a single value
    let values = [42];
    let packed = pack_arr::<1, 8>(values);
    assert(packed[0] != 0);
}

#[test]
fn test_pack_arr_determinism() {
    // Test that packing is deterministic
    let values = [10, 20, 30];
    let packed1 = pack_arr::<3, 8>(values);
    let packed2 = pack_arr::<3, 8>(values);

    for i in 0..packed1.len() {
        assert(packed1[i] == packed2[i]);
    }
}

#[test]
fn test_flatten_arr() {
    // Create test polynomials
    let poly1 = Polynomial::new([1, 2, 3]);
    let poly2 = Polynomial::new([4, -16, 6]);
    let poly3 = Polynomial::new([-7, 8, 9]);

    let polynomials = [poly1, poly2, poly3];
    let result = flatten_arr::<_, _, 4>(polynomials);

    // Same expected values as the old flatten() test
    assert(result[0] == 0x11121310101010101010101010101010101010101010101010101010101010);
    assert(result[1] == 0x14001610101010101010101010101010101010101010101010101010101010);
    assert(result[2] == 0x09181910101010101010101010101010101010101010101010101010101010);
}

#[test]
fn test_flatten_arr_big() {
    let poly1 = Polynomial::new([
        1791218451968394,
        21888242871839275222246405745257275088548364400416034343698198265248580087864,
        21888242871839275222246405745257275088548364400416034343698200542108324633466,
        5430119342984413,
        704811298945172,
        8901715723925099,
        21888242871839275222246405745257275088548364400416034343698203098124042812559,
        21888242871839275222246405745257275088548364400416034343698200215091693880034,
    ]);
    let poly2 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698200314078269634250,
        21888242871839275222246405745257275088548364400416034343698200967285641915872,
        2909990636858607,
        7896103832076587,
        2078397209533893,
        21888242871839275222246405745257275088548364400416034343698199792421452734531,
        614400389245817,
        8290314119277588,
    ]);
    let poly3 = Polynomial::new([
        21888242871839275222246405745257275088548364400416034343698201373175279892906,
        21888242871839275222246405745257275088548364400416034343698201087241869723721,
        6768789983786188,
        635797784303388,
        7610153424227556,
        4633893206538324,
        2016269760615332,
        21888242871839275222246405745257275088548364400416034343698201007080554428142,
    ]);

    let polynomials = [poly1, poly2, poly3];
    let result = flatten_arr::<_, _, 54>(polynomials);

    assert(result[0] == 0x1065d1a8b8b718a0eaf69591f3b0370f30d604a3a9b791134aaa2e86ccdd);
    assert(result[1] == 0x1028105ab1b789411fa010339db66b0fc220f1326bc8e0f1e3f4cc1e02e1);
    assert(result[2] == 0x0f23dfbe7cd76c90f4901299312ddf10a569efe35acef11c0d76f005412b);
    assert(result[3] == 0x107624a8f605dc50f0638a368960421022ecb3cf36b7911d73ff2c27ec14);
    assert(result[4] == 0x0f6013a24e1b9a90f4fd2c158a08481180c2dba8af4cc10242413515171c);
    assert(result[5] == 0x11b0964eb898ce411076805680b85410729c962da53a40f4b44412d0f6ed);
}

#[test]
fn test_flatten_arr_small() {
    let poly1 = Polynomial::new([712345, 104857, 999999, 500001, 123, 654321, 77]);
    let poly2 = Polynomial::new([1, 524287, 888888, 23456, 34567, 765432, 0]);
    let poly3 = Polynomial::new([444444, 333333, 222222, 111111, 987654, 246810, 13579]);

    let polynomials = [poly1, poly2, poly3];
    let result = flatten_arr::<_, _, 20>(polynomials);

    assert(result[0] == 0x1ade991199991f423f17a12110007b19fbf110004d100000100000100000);
    assert(result[1] == 0x10000117ffff1d9038105ba01087071badf8100000100000100000100000);
    assert(result[2] == 0x16c81c15161513640e11b2071f120613c41a10350b100000100000100000);
}
