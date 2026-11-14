// Drop-in Rust module for EFForg/rayhunter (analyzers/markov_entropy.rs)
// Tracks 3GPP RRC/NAS state transitions and flags high-surprise (Stingray) jumps
// or rapid paging/TAU-reject entropy collapse.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RrcNasState {
    IdleCamped = 0,
    MibSib1Sync = 1,
    Sib2CellCfg = 2,
    PagingTmsi = 3,
    RrcConnReq = 4,
    RrcConnSetup = 5,
    NasAttachReq = 6,
    NasAuthReq = 7,
    NasAuthResp = 8,
    SecModeCmd = 9,
    SecModeComp = 10,
    NasAttachAcc = 11,
    RrcReconfig = 12,
    RrcRelease = 13,
    NasIdReqImsi = 14,
    NasTauReject = 15,
}

pub struct MarkovRrcEntropyAnalyzer {
    prev_state: RrcNasState,
    step_idx: usize,
    surprise_threshold_bits: f32,
}

impl MarkovRrcEntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            prev_state: RrcNasState::IdleCamped,
            step_idx: 0,
            surprise_threshold_bits: 8.5, // Flags transitions with P < 0.0027
        }
    }

    /// Evaluates a 3GPP state transition (u -> v) at sequence step t
    /// Returns Some(surprise_bits) if the transition violates carrier homeostasis
    pub fn evaluate_transition(&mut self, next_state: RrcNasState) -> Option<f32> {
        let u = self.prev_state as usize;
        let v = next_state as usize;
        let prob = Self::carrier_baseline_prob(u, v);
        let surprise_bits = -prob.max(1e-6).log2();

        self.prev_state = next_state;
        self.step_idx = (self.step_idx + 1) & 7;

        if surprise_bits >= self.surprise_threshold_bits {
            Some(surprise_bits)
        } else {
            None
        }
    }

    /// Lightweight O(1) lookup for normal 3GPP carrier transition probabilities
    fn carrier_baseline_prob(u: usize, v: usize) -> f32 {
        match (u, v) {
            // Normal 4G LTE Attach & Security Activation chain
            (0, 1) | (1, 2) | (2, 4) | (4, 5) | (5, 6) => 0.82,
            (6, 7) | (7, 8) | (8, 9) | (9, 10) | (10, 11) => 0.88,
            (11, 12) | (12, 13) | (13, 0) | (0, 3) | (3, 4) | (5, 9) => 0.75,
            // Suspicious / Out-of-order Stingray transitions (Pre-Auth IMSI, TAU Reject loops, Paging storms)
            (6, 14) | (14, 14) | (6, 15) | (13, 15) | (3, 3) => 0.0001,
            _ => 0.02,
        }
    }
}