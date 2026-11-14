use chrono::{DateTime, FixedOffset};
use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;
use telcom_parser::lte_rrc::{
    BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_c1, DL_CCCH_MessageType,
    DL_CCCH_MessageType_c1, DL_DCCH_MessageType, DL_DCCH_MessageType_c1, UL_CCCH_MessageType,
    UL_CCCH_MessageType_c1,
};

use super::analyzer::{Analyzer, AnalyzerMetadata, Event, EventType};
use super::information_element::{InformationElement, LteInformationElement};

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

static SURPRISE_MILLIBITS_LUT: [[u16; 16]; 16] = {
    let mut lut = [[10000u16; 16]; 16];
    lut[0][1] = 230; lut[1][2] = 230; lut[2][4] = 230; lut[4][5] = 230; lut[5][6] = 230;
    lut[6][7] = 150; lut[7][8] = 150; lut[8][9] = 150; lut[9][10] = 150; lut[10][11] = 150;
    lut[11][12] = 320; lut[12][13] = 320; lut[13][0] = 320; lut[0][3] = 320; lut[3][4] = 320; lut[5][9] = 320;
    lut[1][0] = 510; lut[2][0] = 510; lut[3][0] = 510; lut[1][1] = 510; lut[2][2] = 510;
    lut[6][14] = 13280; 
    lut[5][14] = 13280; 
    lut[14][14] = 11500;
    lut[6][15] = 9500;  
    lut[13][15] = 9500;
    lut
};

const LOG2_SCALED_LUT: [u16; 9] = [0, 0, 100, 158, 200, 232, 258, 281, 300];

pub struct MarkovEntropyAnalyzer {
    prev_state: u8,
    step_idx: usize,
    recent_window: [u8; 8],
    surprise_threshold_millibits: u16,
    entropy_floor_centibits: u16,
}

impl Default for MarkovEntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkovEntropyAnalyzer {
    pub const fn new() -> Self {
        Self {
            prev_state: RrcNasState::IdleCamped as u8,
            step_idx: 0,
            recent_window: [0, 1, 2, 4, 5, 6, 9, 11],
            surprise_threshold_millibits: 8500,
            entropy_floor_centibits: 100,
        }
    }

    #[inline(always)]
    fn window_shannon_entropy_centibits(&self) -> u16 {
        let mut counts = [0u8; 16];
        let mut i = 0;
        while i < 8 {
            let s = self.recent_window[i] as usize;
            if s < 16 {
                counts[s] += 1;
            }
            i += 1;
        }

        let mut sum_c_log2c = 0u32;
        let mut c_idx = 0;
        while c_idx < 16 {
            let c = counts[c_idx] as usize;
            if c > 0 && c <= 8 {
                sum_c_log2c += (c as u32) * (LOG2_SCALED_LUT[c] as u32);
            }
            c_idx += 1;
        }

        let entropy_scaled = 300_i32 - (sum_c_log2c as i32 / 8);
        if entropy_scaled < 0 { 0 } else { entropy_scaled as u16 }
    }

    #[inline]
    fn map_ie_to_state(ie: &InformationElement) -> Option<RrcNasState> {
        let InformationElement::LTE(inner) = ie else {
            return None;
        };
        match &**inner {
            LteInformationElement::BcchBch(_) => Some(RrcNasState::MibSib1Sync),
            LteInformationElement::BcchDlSch(sch) => match &sch.message {
                BCCH_DL_SCH_MessageType::C1(BCCH_DL_SCH_MessageType_c1::SystemInformationBlockType1(_)) => {
                    Some(RrcNasState::MibSib1Sync)
                }
                BCCH_DL_SCH_MessageType::C1(BCCH_DL_SCH_MessageType_c1::SystemInformation(_)) => {
                    Some(RrcNasState::Sib2CellCfg)
                }
                _ => None,
            },
            LteInformationElement::PCCH(_) => Some(RrcNasState::PagingTmsi),
            LteInformationElement::UlCcch(ul) => match &ul.message {
                UL_CCCH_MessageType::C1(UL_CCCH_MessageType_c1::RrcConnectionRequest(_))
                | UL_CCCH_MessageType::C1(
                    UL_CCCH_MessageType_c1::RrcConnectionReestablishmentRequest(_),
                ) => Some(RrcNasState::RrcConnReq),
                _ => None,
            },
            LteInformationElement::DlCcch(dl) => match &dl.message {
                DL_CCCH_MessageType::C1(DL_CCCH_MessageType_c1::RrcConnectionSetup(_)) => {
                    Some(RrcNasState::RrcConnSetup)
                }
                _ => None,
            },
            LteInformationElement::DlDcch(dcch) => match &dcch.message {
                DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::RrcConnectionReconfiguration(_)) => {
                    Some(RrcNasState::RrcReconfig)
                }
                DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::RrcConnectionRelease(_)) => {
                    Some(RrcNasState::RrcRelease)
                }
                DL_DCCH_MessageType::C1(DL_DCCH_MessageType_c1::SecurityModeCommand(_)) => {
                    Some(RrcNasState::SecModeCmd)
                }
                _ => None,
            },
            LteInformationElement::NAS(nas) => match nas {
                NASMessage::EMMMessage(EMMMessage::EMMAttachRequest(_)) => {
                    Some(RrcNasState::NasAttachReq)
                }
                NASMessage::EMMMessage(EMMMessage::EMMAuthenticationRequest(_)) => {
                    Some(RrcNasState::NasAuthReq)
                }
                NASMessage::EMMMessage(EMMMessage::EMMAuthenticationResponse(_)) => {
                    Some(RrcNasState::NasAuthResp)
                }
                NASMessage::EMMMessage(EMMMessage::EMMSecurityModeCommand(_)) => {
                    Some(RrcNasState::SecModeCmd)
                }
                NASMessage::EMMMessage(EMMMessage::EMMSecurityModeComplete(_)) => {
                    Some(RrcNasState::SecModeComp)
                }
                NASMessage::EMMMessage(EMMMessage::EMMAttachAccept(_))
                | NASMessage::EMMMessage(EMMMessage::EMMAttachComplete(_)) => {
                    Some(RrcNasState::NasAttachAcc)
                }
                NASMessage::EMMMessage(EMMMessage::EMMIdentityRequest(_)) => {
                    Some(RrcNasState::NasIdReqImsi)
                }
                NASMessage::EMMMessage(EMMMessage::EMMTrackingAreaUpdateReject(_))
                | NASMessage::EMMMessage(EMMMessage::EMMAttachReject(_)) => {
                    Some(RrcNasState::NasTauReject)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn evaluate_transition(&mut self, next_state: RrcNasState, packet_num: usize) -> Option<Event> {
        let u = self.prev_state as usize;
        let v = next_state as usize;
        let surprise_mb = SURPRISE_MILLIBITS_LUT[u][v];

        self.recent_window[self.step_idx & 7] = v as u8;
        self.prev_state = v as u8;
        self.step_idx = self.step_idx.wrapping_add(1);

        let window_h_cb = self.window_shannon_entropy_centibits();

        if surprise_mb >= self.surprise_threshold_millibits {
            let event_type = if surprise_mb >= 11000 {
                EventType::High
            } else {
                EventType::Medium
            };
            Some(Event {
                event_type,
                message: format!(
                    "Fixed-point anomaly [State {} -> {}]: surprise = {}.{:03} bits, entropy = {}.{:02} bits (frame {})",
                    u, v, surprise_mb / 1000, surprise_mb % 1000, window_h_cb / 100, window_h_cb % 100, packet_num
                ),
            })
        } else if window_h_cb < self.entropy_floor_bits() {
            Some(Event {
                event_type: EventType::Low,
                message: format!(
                    "3GPP control-plane entropy collapse (entropy = {}.{:02} bits at frame {})",
                    window_h_cb / 100, window_h_cb % 100, packet_num
                ),
            })
        } else {
            None
        }
    }

    #[inline(always)]
    const fn entropy_floor_bits(&self) -> u16 {
        self.entropy_floor_centibits
    }
}

impl Analyzer for MarkovEntropyAnalyzer {
    fn metadata() -> AnalyzerMetadata {
        AnalyzerMetadata {
            key: "markov_entropy".into(),
            default_enabled: true,
            name: "Fixed-Point 3GPP Markov & Entropy Analyzer".into(),
            description: "Zero-alloc O(1) fixed-point control-plane anomaly detector optimized for embedded Qualcomm targets.".into(),
            version: 2,
        }
    }

    fn analyze_information_element(
        &mut self,
        ie: &InformationElement,
        packet_num: usize,
        _timestamp: DateTime<FixedOffset>,
    ) -> Option<Event> {
        let next_state = Self::map_ie_to_state(ie)?;
        self.evaluate_transition(next_state, packet_num)
    }
}
