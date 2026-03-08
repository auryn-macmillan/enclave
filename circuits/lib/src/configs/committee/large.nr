// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Large committee size (39-of-80 threshold).
///
/// The threshold T must satisfy T <= (N_PARTIES - 1) / 2 due to the
/// Reed-Solomon parity check matrix construction.  For N_PARTIES = 80
/// the maximum threshold is 39.

/// Number of parties.
pub global N_PARTIES: u32 = 80;
/// Threshold.
pub global T: u32 = 39;
/// Number of honest parties.
pub global H: u32 = 80;
