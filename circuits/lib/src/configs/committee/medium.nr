// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Medium committee size (9-of-20 threshold).
///
/// The threshold T must satisfy T <= (N_PARTIES - 1) / 2 due to the
/// Reed-Solomon parity check matrix construction.  For N_PARTIES = 20
/// the maximum threshold is 9.

/// Number of parties.
pub global N_PARTIES: u32 = 20;
/// Threshold.
pub global T: u32 = 9;
/// Number of honest parties.
pub global H: u32 = 20;
