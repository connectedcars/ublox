use super::{
    ubx_checksum, MemWriter, Position, UbxChecksumCalc, UbxPacketCreator, UbxPacketMeta,
    UbxUnknownPacketRef, SYNC_CHAR_1, SYNC_CHAR_2,
};
use crate::error::{MemWriterError, ParserError};
use bitflags::bitflags;
use chrono::prelude::*;
use core::fmt::{self, Debug};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::float::FloatCore;
use serde::{Deserialize, Serialize};
use ublox_derive::{
    define_recv_packets, ubx_extend, ubx_extend_bitflags, ubx_packet_recv, ubx_packet_recv_send,
    ubx_packet_send,
};

///  Position solution in ECEF
#[ubx_packet_recv]
#[ubx(class = 1, id = 1, fixed_payload_len = 20)]
struct NavPosEcef {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// ECEF X coordinate
    ecef_x: i32,

    /// ECEF Y coordinate
    ecef_y: i32,

    /// ECEF Z coordinate
    ecef_z: i32,

    /// Position Accuracy Estimate
    p_acc: u32,
}

///  Velocity solution in ECEF
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x11, fixed_payload_len = 20)]
struct NavVelEcef {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// ECEF X velocity
    ecef_vx: i32,

    /// ECEF Y velocity
    ecef_vy: i32,

    /// ECEF Z velocity
    ecef_vz: i32,

    /// Speed Accuracy Estimate
    s_acc: u32,
}

///  GPS time solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x20, fixed_payload_len = 16)]
struct NavTimeGps {
    /// GPS time of the week of the navigation epoch
    itow: u32,

    /// Fractional part of ITOW (range: +/- 500000). The precise GPS time of week in seconds is: (iTOW * 1e-3) + (fTOW * 1e-9)
    ftow: i32,

    /// GPS week number of the navitgation epoch
    week: i16,

    /// GPS leap seconds (GPS-UTC)
    leap_s: i8,

    /// Validity Flags
    #[ubx(map_type = NavTimeGpsFlags)]
    valid: u8,

    /// Time Accuracy Estimate
    t_acc: u32,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Validity flags for `NavTimeGps`
    pub struct NavTimeGpsFlags: u8 {
        const TOW_VALID = 1;
        const WEEK_VALID = 2;
        const LEAP_S_VALID = 4;
    }
}

///  Position solution in ECEF
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x60, fixed_payload_len = 16)]
struct NavAopStatus {
    /// GPS time of the week of the navigation epoch
    itow: u32,

    /// AssistNow Autonomous configuration
    #[ubx(map_type = NavAopStatusCfg)]
    aop_cfg: u8,

    /// AssistNow Autonomous subsystem is idle (0) or running (not 0)
    status: u8,

    /// Reserved
    reserved: [u8; 10],
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Bitfield aopCfg for `NavAopStatus`
    pub struct NavAopStatusCfg: u8 {
        const USE_AOP = 1;
    }
}

///  Position solution in ECEF
#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x60, fixed_payload_len = 8)]
struct MgaAck {
    /// Type of acknowledgment:
    /// 0: The message was not used by the
    /// receiver (see infoCode field for an
    /// indication of why)
    /// 1: The message was accepted for use by
    /// the receiver (the infoCode field will be 0)
    ack_type: u8,

    /// Message version (0x00 for this version)
    version: u8,

    /// Provides greater information on what the
    /// receiver chose to do with the message contents:
    /// 0: The receiver accepted the data
    /// 1: The receiver does not know the time so it cannot use the data (To resolve this a UBX-MGA-INI-TIME_UTC message should be supplied first)
    /// 2: The message version is not supported by the receiver
    /// 3: The message size does not match the message version
    /// 4: The message data could not be stored to the database
    /// 5: The receiver is not ready to use the message data
    /// 6: The message type is unknown
    info_code: u8,

    /// UBX message ID of the acknowledged message
    msg_id: u8,

    /// The first 4 bytes of the acknowledged message's payload
    msg_payload_start: [u8; 4],
}

/// Geodetic Position Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 2, fixed_payload_len = 28)]
struct NavPosLlh {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// Longitude
    #[ubx(map_type = f64, scale = 1e-7, alias = lon_degrees)]
    lon: i32,

    /// Latitude
    #[ubx(map_type = f64, scale = 1e-7, alias = lat_degrees)]
    lat: i32,

    /// Height above Ellipsoid
    #[ubx(map_type = f64, scale = 1e-3)]
    height_meters: i32,

    /// Height above mean sea level
    #[ubx(map_type = f64, scale = 1e-3)]
    height_msl: i32,

    /// Horizontal Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-3)]
    h_ack: u32,

    /// Vertical Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-3)]
    v_acc: u32,
}

/// Velocity Solution in NED
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x12, fixed_payload_len = 36)]
struct NavVelNed {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// north velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_north: i32,

    /// east velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_east: i32,

    /// down velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    vel_down: i32,

    /// Speed 3-D (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_3d: u32,

    /// Ground speed (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ground_speed: u32,

    /// Heading of motion 2-D (degrees)
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_degrees)]
    heading: i32,

    /// Speed Accuracy Estimate (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_accuracy_estimate: u32,

    /// Course / Heading Accuracy Estimate (degrees)
    #[ubx(map_type = f64, scale = 1e-5)]
    course_heading_accuracy_estimate: u32,
}

/// Navigation Position Velocity Time Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x07, fixed_payload_len = 92)]
struct NavPosVelTime {
    /// GPS Millisecond Time of Week
    itow: u32,
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    min: u8,
    sec: u8,
    valid: u8,
    time_accuracy: u32,
    nanosecond: i32,

    /// GNSS fix Type
    #[ubx(map_type = GpsFix)]
    fix_type: u8,
    #[ubx(map_type = NavPosVelTimeFlags)]
    flags: u8,
    #[ubx(map_type = NavPosVelTimeFlags2)]
    flags2: u8,
    num_satellites: u8,
    #[ubx(map_type = f64, scale = 1e-7, alias = lon_degrees)]
    lon: i32,
    #[ubx(map_type = f64, scale = 1e-7, alias = lat_degrees)]
    lat: i32,

    /// Height above Ellipsoid
    #[ubx(map_type = f64, scale = 1e-3)]
    height_meters: i32,

    /// Height above mean sea level
    #[ubx(map_type = f64, scale = 1e-3)]
    height_msl: i32,
    horiz_accuracy: u32,
    vert_accuracy: u32,

    /// north velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_north: i32,

    /// east velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_east: i32,

    /// down velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    vel_down: i32,

    /// Ground speed (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    ground_speed: u32,

    /// Heading of motion 2-D (degrees)
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_degrees)]
    heading: i32,

    /// Speed Accuracy Estimate (m/s)
    #[ubx(map_type = f64, scale = 1e-3)]
    speed_accuracy_estimate: u32,

    /// Heading accuracy estimate (both motionand vehicle) (degrees)
    #[ubx(map_type = f64, scale = 1e-5)]
    heading_accuracy_estimate: u32,

    /// Position DOP
    pdop: u16,
    reserved1: [u8; 6],
    #[ubx(map_type = f64, scale = 1e-5, alias = heading_of_vehicle_degrees)]
    heading_of_vehicle: i32,
    #[ubx(map_type = f64, scale = 1e-2, alias = magnetic_declination_degrees)]
    magnetic_declination: i16,
    #[ubx(map_type = f64, scale = 1e-2, alias = magnetic_declination_accuracy_degrees)]
    magnetic_declination_accuracy: u16,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Fix status flags for `NavPosVelTime`
    pub struct NavPosVelTimeFlags: u8 {
        /// position and velocity valid and within DOP and ACC Masks
        const GPS_FIX_OK = 1;
        /// DGPS used
        const DIFF_SOLN = 2;
        /// 1 = heading of vehicle is valid
        const HEAD_VEH_VALID = 0x20;
        const CARR_SOLN_FLOAT = 0x40;
        const CARR_SOLN_FIXED = 0x80;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Additional flags for `NavPosVelTime`
    pub struct NavPosVelTimeFlags2: u8 {
        /// 1 = information about UTC Date and Time of Day validity confirmation
        /// is available. This flag is only supported in Protocol Versions
        /// 19.00, 19.10, 20.10, 20.20, 20.30, 22.00, 23.00, 23.01,27 and 28.
        const CONFIRMED_AVAI = 0x20;
        /// 1 = UTC Date validity could be confirmed
        /// (confirmed by using an additional independent source)
        const CONFIRMED_DATE = 0x40;
        /// 1 = UTC Time of Day could be confirmed
        /// (confirmed by using an additional independent source)
        const CONFIRMED_TIME = 0x80;
    }
}

///  Receiver Navigation Status
#[ubx_packet_recv]
#[ubx(class = 1, id = 3, fixed_payload_len = 16)]
struct NavStatus {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// GPS fix Type, this value does not qualify a fix as

    /// valid and within the limits
    #[ubx(map_type = GpsFix)]
    fix_type: u8,

    /// Navigation Status Flags
    #[ubx(map_type = NavStatusFlags)]
    flags: u8,

    /// Fix Status Information
    #[ubx(map_type = FixStatusInfo)]
    fix_stat: u8,

    /// further information about navigation output
    #[ubx(map_type = NavStatusFlags2)]
    flags2: u8,

    /// Time to first fix (millisecond time tag)
    time_to_first_fix: u32,

    /// Milliseconds since Startup / Reset
    uptime_ms: u32,
}

/// Dilution of precision
#[ubx_packet_recv]
#[ubx(class = 1, id = 4, fixed_payload_len = 18)]
struct NavDop {
    /// GPS Millisecond Time of Week
    itow: u32,
    #[ubx(map_type = f32, scale = 1e-2)]
    geometric_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    position_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    time_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    vertical_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    horizontal_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    northing_dop: u16,
    #[ubx(map_type = f32, scale = 1e-2)]
    easting_dop: u16,
}

/// Navigation Solution Information
#[ubx_packet_recv]
#[ubx(class = 1, id = 6, fixed_payload_len = 52)]
struct NavSolution {
    /// GPS Millisecond Time of Week
    itow: u32,

    /// Fractional part of iTOW (range: +/-500000).
    ftow_ns: i32,

    /// GPS week number of the navigation epoch
    week: i16,

    /// GPS fix Type
    #[ubx(map_type = GpsFix)]
    fix_type: u8,

    /// Navigation Status Flags
    #[ubx(map_type = NavStatusFlags)]
    flags: u8,

    /// ECEF X coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_x: i32,

    /// ECEF Y coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_y: i32,

    /// ECEF Z coordinate (meters)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_z: i32,

    /// 3D Position Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-2)]
    position_accuracy_estimate: u32,

    /// ECEF X velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vx: i32,

    /// ECEF Y velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vy: i32,

    /// ECEF Z velocity (m/s)
    #[ubx(map_type = f64, scale = 1e-2)]
    ecef_vz: i32,

    /// Speed Accuracy Estimate
    #[ubx(map_type = f64, scale = 1e-2)]
    speed_accuracy_estimate: u32,

    /// Position DOP
    #[ubx(map_type = f32, scale = 1e-2)]
    pdop: u16,
    reserved1: u8,

    /// Number of SVs used in Nav Solution
    num_sv: u8,
    reserved2: [u8; 4],
}

/// GPS fix Type
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum GpsFix {
    NoFix = 0,
    DeadReckoningOnly = 1,
    Fix2D = 2,
    Fix3D = 3,
    GPSPlusDeadReckoning = 4,
    TimeOnlyFix = 5,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Navigation Status Flags
    pub struct NavStatusFlags: u8 {
        /// position and velocity valid and within DOP and ACC Masks
        const GPS_FIX_OK = 1;
        /// DGPS used
        const DIFF_SOLN = 2;
        /// Week Number valid
        const WKN_SET = 4;
        /// Time of Week valid
        const TOW_SET = 8;
    }
}

/// Fix Status Information
#[repr(transparent)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct FixStatusInfo(u8);

impl FixStatusInfo {
    pub const fn has_pr_prr_correction(self) -> bool {
        (self.0 & 1) == 1
    }
    pub fn map_matching(self) -> MapMatchingStatus {
        let bits = (self.0 >> 6) & 3;
        match bits {
            0 => MapMatchingStatus::None,
            1 => MapMatchingStatus::Valid,
            2 => MapMatchingStatus::Used,
            3 => MapMatchingStatus::Dr,
            _ => unreachable!(),
        }
    }
    pub const fn from(x: u8) -> Self {
        Self(x)
    }
}

impl fmt::Debug for FixStatusInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixStatusInfo")
            .field("has_pr_prr_correction", &self.has_pr_prr_correction())
            .field("map_matching", &self.map_matching())
            .finish()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum MapMatchingStatus {
    None = 0,
    /// valid, i.e. map matching data was received, but was too old
    Valid = 1,
    /// used, map matching data was applied
    Used = 2,
    /// map matching was the reason to enable the dead reckoning
    /// gpsFix type instead of publishing no fix
    Dr = 3,
}

/// Further information about navigation output
/// Only for FW version >= 7.01; undefined otherwise
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum NavStatusFlags2 {
    Acquisition = 0,
    Tracking = 1,
    PowerOptimizedTracking = 2,
    Inactive = 3,
}

/// Space vehicle information
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x26, fixed_payload_len = 24)]
struct NavTimeLs {
    /// GPS Millisecond Time of Week
    itow: u32,
    /// Message version (0x00 for this version)
    version: u8,
    /// Reserved
    reserved1: [u8; 3],
    /// Information source for the current number of leap seconds
    #[ubx(map_type = LsSource)]
    src_of_curr_ls: u8,
    /// Current number of leap seconds since
    /// start of GPS time (Jan 6, 1980). It reflects
    /// how much GPS time is ahead of UTC time.
    /// Galileo number of leap seconds is the
    /// same as GPS. BeiDou number of leap
    /// seconds is 14 less than GPS. GLONASS
    /// follows UTC time, so no leap seconds.
    curr_ls: i8,
    /// Information source for the future leap second event.
    #[ubx(map_type = LsSourceChange)]
    src_of_ls_change: u8,
    /// Future leap second change if one is
    /// scheduled. +1 = positive leap second, -1 =
    /// negative leap second, 0 = no future leap
    /// second event scheduled or no information
    /// available
    ls_change: i8,
    /// Number of seconds until the next leap
    /// second event, or from the last leap second
    /// event if no future event scheduled. If > 0
    /// event is in the future, = 0 event is now, < 0
    /// event is in the past. Valid only if
    /// validTimeToLsEvent = 1.
    time_to_ls_event: i32,
    /// GPS week number (WN) of the next leap
    /// second event or the last one if no future
    /// event scheduled. Valid only if
    /// validTimeToLsEvent = 1.
    date_of_ls_gps_wn: u16,
    /// GPS day of week number (DN) for the next
    /// leap second event or the last one if no
    /// future event scheduled. Valid only if
    /// validTimeToLsEvent = 1. (GPS and Galileo
    /// DN: from 1 = Sun to 7 = Sat. BeiDou DN:
    /// from 0 = Sun to 6 = Sat.)
    date_of_ls_gps_dn: u16,
    /// Reserved
    reserved2: [u8; 3],
    /// Validity flags
    #[ubx(map_type = LsValidityFlags)]
    valid: u8,
}

/// Information source for the current number of leap seconds
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum LsSource {
    /// hardcoded in the firmware, can be outdated
    Default = 0,
    /// Derived from time difference between GPS and GLONASS time
    Derived = 1,
    GPS = 2,
    SBAS = 3,
    Beidou = 4,
    Galileo = 5,
    AidedData = 6,
    Configured = 7,
    NavIC = 8,
    Unknown = 255,
}

/// Information source for the future leap second event.
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum LsSourceChange {
    NoSource = 0,
    GPS = 2,
    SBAS = 3,
    Beidou = 4,
    Galileo = 5,
    GLONASS = 6,
    NavIC = 7,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Validity flags for the leap second information
    pub struct LsValidityFlags: u8 {
        /// Valid current number of leap seconds value
        const VALID_CURR_LS = 1;
        /// Valid time to next leap second event or from the last leap second event if no future event scheduled
        const VALID_TIME_TO_LS_EVENT = 2;
    }
}

/// Space vehicle information
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x30, max_payload_len = 3068)]
struct NavSvInfo {
    /// GPS Millisecond Time of Week
    itow: u32,
    /// Number of channels
    numch: u8,
    /// Bitmask
    #[ubx(map_type = GlobalFlags)]
    global_flags: u8,
    /// Reserved
    reserved1: u16,
    #[ubx(map_type = Vec<nav_svinfo::SvInfo>, from = nav_svinfo::convert_to_payload)]
    data: [u8; 0],
}

/// ChipGen
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum GlobalFlags {
    AntarisAntaris4 = 0,
    Ublox5 = 1,
    Ublox6 = 2,
    Ublox7 = 3,
    Ublox8UbloxM8 = 4,
}

/// Bitfield flags per satellite
#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Fix status flags for `NavPosVelTime`
    pub struct BitFieldFlags: u8 {
        /// SV is used for navigation
        const SV_USED = 1;
        /// Differential correction data is available for this SV
        const DIFF_CORR = 2;
        /// Orbit information is available for this SV (Ephemeris or Almanac)
        const ORBIT_AVAILABLE = 4;
        /// Orbit information is Ephemeris
        const ORBIT_EPH_AVAILABLE = 8;
        /// SV is unhealthy / shall not be used
        const UNHEALTHY = 16;
        /// Orbit information is Almanac Plus
        const  ORBIT_ALM_AVAILABLE = 32;
        /// Orbit information is AssistNow Autonomous
        const  ORBIT_AOP_AVAILABLE = 64;
        /// Carrier smoothed pseudorange used
        const SMOOTHED = 128;
    }
}

/// Signal Quality
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BitFieldQuality {
    NoSignal = 0,
    SearchingSignal = 1,
    SignalAcquired = 2,
    SignalDetectedButUnusable = 3,
    CodeLockedAndTimeSynchronized = 4,
    CodeAndCarrierLockedAndTimeSynchronized = 5,
    CodeAndCarrierLockedAndTimeSynchronizedAndPseudorangeValid = 6,
    CodeAndCarrierLockedAndTimeSynchronizedAndPseudorangeAndCodePhaseValid = 7,
}

mod nav_svinfo {
    use super::*;

    #[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct SvInfo {
        /// Channel number, 255 for SVs not assigned to a channel
        chn: u8,
        /// Satellite ID, see Satellite Numbering for assignment
        svid: u8,
        /// Bitmask
        flags: BitFieldFlags,
        /// Bitfield
        quality: BitFieldQuality,
        /// Carrier to Noise Ratio (Signal Strength) in dBHZ
        cno: u8,
        /// Elevation in integer degrees
        elev: i8,
        /// Azimuth in integer degrees
        azim: i16,
        /// Pseudo range residual in centimeters
        pr_res: i32,
    }

    pub(crate) fn convert_to_payload(bytes: &[u8]) -> Vec<SvInfo> {
        let mut res = Vec::new();
        let mut iter = bytes.iter();
        while iter.len() >= 12 {
            let chn = iter.next().unwrap();
            let svid = iter.next().unwrap();
            let flags = iter.next().unwrap();
            let quality = iter.next().unwrap();
            let cno = iter.next().unwrap();
            let elev = iter.next().unwrap();
            let azim = [*iter.next().unwrap(), *iter.next().unwrap()];
            let pr_res = [
                *iter.next().unwrap(),
                *iter.next().unwrap(),
                *iter.next().unwrap(),
                *iter.next().unwrap(),
            ];
            res.push(SvInfo {
                chn: *chn,
                svid: *svid,
                flags: BitFieldFlags::from(*flags),
                quality: BitFieldQuality::from(*quality),
                cno: *cno,
                elev: i8::from_le_bytes([*elev]),
                azim: i16::from_le_bytes(azim),
                pr_res: i32::from_le_bytes(pr_res),
            });
        }
        res
    }
}

/// SBAS status data
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x32, max_payload_len = 3072)]
struct NavSbas {
    /// GPS Millisecond Time of Week
    itow: u32,
    /// PRN Number of the GEO where correction and integrity data is used from
    geo: u8,
    /// SBAS Mode
    #[ubx(map_type = SbasMode)]
    mode: u8,
    /// SBAS System (WAAS/EGNOS/...)
    #[ubx(map_type = SbasSystem)]
    sys: i8,
    /// SBAS Services available
    #[ubx(map_type = ServiceBitFlags)]
    service: u8,
    /// Number of SV data following
    cnt: u8,
    #[ubx(map_type = BitFieldStatusFlags)]
    /// SBAS status flags
    status_flags: u8,
    /// Reserved
    reserved1: u16,
    #[ubx(map_type = Vec<nav_sbas::SbasInfo>, from = nav_sbas::convert_to_payload)]
    data: [u8; 0],
}

/// Signal Quality
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SbasMode {
    Disabled = 0,
    EnabledIntegrity = 1,
    EnabledTestMode = 3,
}

/// SBAS System (WAAS/EGNOS/...)
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(i8)]
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SbasSystem {
    Unknown = -1,
    WAAS = 0,
    EGNOS = 1,
    MSAS = 2,
    GAGAN = 3,
    GPS = 16,
}

/// SBAS Services available bitflags
#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Fix status flags for `NavPosVelTime`
    pub struct ServiceBitFlags: u8 {
        /// GEO may be used as ranging source
        const RANGING = 1;
        /// GEO is providing correction data
        const CORRECTIONS = 2;
        /// GEO is providing integrity
        const INTEGRITY = 4;
        /// GEO is in test mode
        const TESTMODE = 8;
        /// Problem with signal or broadcast data indicated
        const BAD = 16;
    }
}

/// SBAS status flags
#[ubx_extend]
#[ubx(from, rest_reserved)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BitFieldStatusFlags {
    Unknown = 0,
    NoIntegrity = 1,
    GoodIntegrity = 2,
}

mod nav_sbas {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct SbasInfo {
        /// SV ID
        svid: u8,
        /// Flags for this SV
        flags: BitFieldStatusFlags,
        /// Monitoring status
        udre: u8,
        /// System (WAAS/EGNOS/...) same as SYS
        svsys: SbasSystem,
        /// Services available same as SERVICE
        svservice: ServiceBitFlags,
        /// Reserved
        reserved2: u8,
        /// Pseudo Range correction in [cm]
        prc: i16,
        /// Reserved
        reserved3: u16,
        /// Ionosphere correction in [cm]
        ic: i16,
    }

    pub(crate) fn convert_to_payload(bytes: &[u8]) -> Vec<SbasInfo> {
        let mut res = Vec::new();
        let mut iter = bytes.iter();
        while iter.len() >= 12 {
            let svid = iter.next().unwrap();
            let flags = iter.next().unwrap();
            let udre = iter.next().unwrap();
            let svsys = iter.next().unwrap();
            let svservice = iter.next().unwrap();
            let reserved2 = iter.next().unwrap();
            let prc = [*iter.next().unwrap(), *iter.next().unwrap()];
            let reserved3 = [*iter.next().unwrap(), *iter.next().unwrap()];
            let ic = [*iter.next().unwrap(), *iter.next().unwrap()];
            res.push(SbasInfo {
                svid: *svid,
                flags: BitFieldStatusFlags::from(*flags),
                udre: *udre,
                svsys: SbasSystem::from(*svsys as i8),
                svservice: ServiceBitFlags::from(*svservice),
                reserved2: *reserved2,
                prc: i16::from_le_bytes(prc),
                reserved3: u16::from_le_bytes(reserved3),
                ic: i16::from_le_bytes(ic),
            });
        }
        res
    }
}

/// SBAS status data
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x35, max_payload_len = 3068)]
struct NavSat {
    /// GPS Millisecond Time of Week
    itow: u32,
    /// Message version (0x01 for this version)
    version: u8,
    /// Number of satellites
    numsvs: u8,
    /// Reserved
    reserved1: i8,
    #[ubx(map_type = Vec<nav_sat::SatInfo>, from = nav_sat::convert_to_payload)]
    data: [u8; 0],
}

/// Sat Bitmask
#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Fix status flags for `NavPosVelTime`
    pub struct _NavServiceBitFlags: u32 {
        /// GEO may be used as ranging source
        const QUALITY_IND = 1;
        /// GEO is providing correction data
        const SV_USED = 2;
        /// GEO is providing integrity
        const HEALTH = 4;
        /// GEO is in test mode
        const TESTMODE = 8;
        /// Problem with signal or broadcast data indicated
        const BAD = 16;
    }
}

mod nav_sat {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct SatInfo {
        /// GNSS identifier
        gnssid: u8,
        /// Satellite identifier
        svid: u8,
        /// Carrier to noise ratio (signal strength) in dBHz
        cno: u8,
        /// Elevation (range: +/-90), unknown if out of range
        elev: i8,
        /// Azimuth (range 0-360), unknown if elevation is out of range
        azim: i16,
        /// Pseudorange residual in meters
        prres: i16,
        /// Bitfield flags
        flags: NavServiceBitFlags,
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct NavServiceBitFlags {
        /// Signal quality indicator
        quality_ind: QualityIndicator,
        /// Signal in the subset specified in Signal Identifiers is currently being used for navigation
        sv_used: bool,
        /// Signal health flag
        health: Health,
        /// Differential correction data is available for this SV
        diff_corr: bool,
        /// Carrier smoothed pseudorange used
        smoothed: bool,
        /// Orbit source
        orbit_source: OrbitSource,
        /// Ephemeris is available for this SV
        eph_available: bool,
        /// Almanac is available for this SV
        alm_available: bool,
        /// AssistNow Offline data is available for this SV
        ano_available: bool,
        /// AssistNow Autonomous data is available for this SV
        aop_available: bool,
        /// SBAS corrections have been used for a signal
        sbas_corr_used: bool,
        /// RTCM corrections have been used for a signal
        rtcm_corr_used: bool,
        /// QZSS SLAS corrections have been used for a signal
        slas_corr_used: bool,
        /// SPARTN corrections have been used for a signal
        spartn_corr_used: bool,
        /// Pseudorange corrections have been used for a signal
        pr_corr_used: bool,
        /// Carrier range corrections have been used for a signal
        cr_corr_used: bool,
        /// Range rate (Doppler) corrections have been used for a signal
        do_corr_used: bool,
        /// CLAS corrections have been used for a signal
        clas_corr_used: bool,
    }

    impl NavServiceBitFlags {
        fn from_u32(long: u32) -> Self {
            Self {
                quality_ind: QualityIndicator::from((long & 0b111) as u8),
                sv_used: (long & 0b1111) != 0,
                health: Health::from(((long >> 4) & 0b11) as u8),
                diff_corr: (long & 0b1111111) != 0,
                smoothed: (long & 0b11111111) != 0,
                orbit_source: OrbitSource::from(((long >> 8) & 0b111) as u8),
                eph_available: (long & 0b11111111111) != 0,
                alm_available: (long & 0b111111111111) != 0,
                ano_available: (long & 0b1111111111111) != 0,
                aop_available: (long & 0b11111111111111) != 0,
                sbas_corr_used: (long & 0b1111111111111111) != 0,
                rtcm_corr_used: (long & 0b11111111111111111) != 0,
                slas_corr_used: (long & 0b111111111111111111) != 0,
                spartn_corr_used: (long & 0b1111111111111111111) != 0,
                pr_corr_used: (long & 0b11111111111111111111) != 0,
                cr_corr_used: (long & 0b111111111111111111111) != 0,
                do_corr_used: (long & 0b1111111111111111111111) != 0,
                clas_corr_used: (long & 0b11111111111111111111111) != 0,
            }
        }
    }

    /// Signal quality indicator
    #[ubx_extend]
    #[ubx(from, rest_reserved)]
    #[repr(u8)]
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub enum QualityIndicator {
        NoSignal = 0,
        SearchingSignal = 1,
        SignalAcquired = 2,
        SignalDetectedButUnusable = 3,
        CodeLockedAndTimeSynchronized = 4,
        CodeAndCarrierLockedAndTimeSynchronized = 5,
        CodeAndCarrierLockedAndTimeSynchronizedAndPseudorangeValid = 6,
        CodeAndCarrierLockedAndTimeSynchronizedAndPseudorangeAndCodePhaseValid = 7,
    }

    /// Signal health flag
    #[ubx_extend]
    #[ubx(from, rest_reserved)]
    #[repr(u8)]
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub enum Health {
        Unknown = 0,
        Healthy = 1,
        Unhealthy = 2,
    }

    /// Orbit source
    #[ubx_extend]
    #[ubx(from, rest_reserved)]
    #[repr(u8)]
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub enum OrbitSource {
        NoOrbitInformation = 0,
        EphemerIsUsed = 1,
        AlmanacIsUsed = 2,
        AssistNowOfflineOrbitIsUsed = 3,
        AssistNowAutonomousOrbitIsUsed = 4,
        OtherOrbitInformationIsUsed = 5,
        OtherOrbitInformationIsUsed2 = 6,
        OtherOrbitInformationIsUsed3 = 7,
    }

    pub(crate) fn convert_to_payload(bytes: &[u8]) -> Vec<SatInfo> {
        let mut res = Vec::new();
        let mut iter = bytes.iter();
        while iter.len() >= 12 {
            let gnssid = iter.next().unwrap();
            let svid = iter.next().unwrap();
            let cno = iter.next().unwrap();
            let elev = iter.next().unwrap();
            let azim = [*iter.next().unwrap(), *iter.next().unwrap()];
            let prres = [*iter.next().unwrap(), *iter.next().unwrap()];
            let flags = [
                *iter.next().unwrap(),
                *iter.next().unwrap(),
                *iter.next().unwrap(),
                *iter.next().unwrap(),
            ];
            res.push(SatInfo {
                gnssid: *gnssid,
                svid: *svid,
                cno: *cno,
                elev: *elev as i8,
                azim: i16::from_le_bytes(azim),
                prres: i16::from_le_bytes(prres),
                flags: NavServiceBitFlags::from_u32(u32::from_le_bytes(flags)),
            });
        }
        res
    }
}

#[ubx_packet_send]
#[ubx(
    class = 0x0B,
    id = 0x01,
    fixed_payload_len = 48,
    flags = "default_for_builder"
)]
struct AidIni {
    ecef_x_or_lat: i32,
    ecef_y_or_lon: i32,
    ecef_z_or_alt: i32,
    pos_accuracy: u32,
    time_cfg: u16,
    week_or_ym: u16,
    tow_or_hms: u32,
    tow_ns: i32,
    tm_accuracy_ms: u32,
    tm_accuracy_ns: u32,
    clk_drift_or_freq: i32,
    clk_drift_or_freq_accuracy: u32,
    flags: u32,
}

impl AidIniBuilder {
    pub fn set_position(mut self, pos: Position) -> Self {
        self.ecef_x_or_lat = (pos.lat * 10_000_000.0) as i32;
        self.ecef_y_or_lon = (pos.lon * 10_000_000.0) as i32;
        self.ecef_z_or_alt = (pos.alt * 100.0) as i32; // Height is in centimeters, here
        self.flags |= (1 << 0) | (1 << 5);
        self
    }

    pub fn set_time(mut self, tm: DateTime<Utc>) -> Self {
        self.week_or_ym = (match tm.year_ce() {
            (true, yr) => yr - 2000,
            (false, _) => {
                panic!("AID-INI packet only supports years after 2000");
            }
        } * 100
            + tm.month0()) as u16;
        self.tow_or_hms = tm.hour() * 10000 + tm.minute() * 100 + tm.second();
        self.tow_ns = tm.nanosecond() as i32;
        self.flags |= (1 << 1) | (1 << 10);
        self
    }
}

/// ALP client requests AlmanacPlus data from server
#[ubx_packet_recv]
#[ubx(class = 0x0B, id = 0x32, fixed_payload_len = 16)]
struct AlpSrv {
    pub id_size: u8,
    pub data_type: u8,
    pub offset: u16,
    pub size: u16,
    pub file_id: u16,
    pub data_size: u16,
    pub id1: u8,
    pub id2: u8,
    pub id3: u32,
}

/// Messages in this class are sent as a result of a CFG message being
/// received, decoded and processed by thereceiver.
#[ubx_packet_recv]
#[ubx(class = 5, id = 1, fixed_payload_len = 2)]
struct AckAck {
    /// Class ID of the Acknowledged Message
    class: u8,

    /// Message ID of the Acknowledged Message
    msg_id: u8,
}

impl<'a> AckAckRef<'a> {
    pub fn is_ack_for<T: UbxPacketMeta>(&self) -> bool {
        self.class() == T::CLASS && self.msg_id() == T::ID
    }
}

/// Message Not-Acknowledge
#[ubx_packet_recv]
#[ubx(class = 5, id = 0, fixed_payload_len = 2)]
struct AckNak {
    /// Class ID of the Acknowledged Message
    class: u8,

    /// Message ID of the Acknowledged Message
    msg_id: u8,
}

impl<'a> AckNakRef<'a> {
    pub fn is_nak_for<T: UbxPacketMeta>(&self) -> bool {
        self.class() == T::CLASS && self.msg_id() == T::ID
    }
}

/// Reset Receiver / Clear Backup Data Structures
#[ubx_packet_send]
#[ubx(class = 6, id = 4, fixed_payload_len = 4)]
struct CfgRst {
    /// Battery backed RAM sections to clear
    #[ubx(map_type = NavBbrMask)]
    nav_bbr_mask: u16,

    /// Reset Type
    #[ubx(map_type = ResetMode)]
    reset_mode: u8,
    reserved1: u8,
}

#[ubx_extend_bitflags]
#[ubx(into_raw, rest_reserved)]
bitflags! {
    /// Battery backed RAM sections to clear
    pub struct NavBbrMask: u16 {
        const EPHEMERIS = 1;
        const ALMANACH = 2;
        const HEALTH = 4;
        const KLOBUCHARD = 8;
        const POSITION = 16;
        const CLOCK_DRIFT = 32;
        const OSCILATOR_PARAMETER = 64;
        const UTC_CORRECTION_PARAMETERS = 0x80;
        const RTC = 0x100;
        const SFDR_PARAMETERS = 0x800;
        const SFDR_VEHICLE_MONITORING_PARAMETERS = 0x1000;
        const TCT_PARAMETERS = 0x2000;
        const AUTONOMOUS_ORBIT_PARAMETERS = 0x8000;
    }
}

/// Predefined values for `NavBbrMask`
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct NavBbrPredefinedMask(u16);

impl From<NavBbrPredefinedMask> for NavBbrMask {
    fn from(x: NavBbrPredefinedMask) -> Self {
        Self::from_bits_truncate(x.0)
    }
}

impl NavBbrPredefinedMask {
    pub const HOT_START: NavBbrPredefinedMask = NavBbrPredefinedMask(0);
    pub const WARM_START: NavBbrPredefinedMask = NavBbrPredefinedMask(1);
    pub const COLD_START: NavBbrPredefinedMask = NavBbrPredefinedMask(0xFFFF);
}

/// Reset Type
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum ResetMode {
    /// Hardware reset (Watchdog) immediately
    HardwareResetImmediately = 0,
    ControlledSoftwareReset = 0x1,
    ControlledSoftwareResetGpsOnly = 0x02,
    /// Hardware reset (Watchdog) after shutdown (>=FW6.0)
    HardwareResetAfterShutdown = 0x04,
    ControlledGpsStop = 0x08,
    ControlledGpsStart = 0x09,
}

impl ResetMode {
    const fn into_raw(self) -> u8 {
        self as u8
    }
}

/// Port Configuration for UART
#[ubx_packet_recv_send]
#[ubx(class = 0x06, id = 0x00, fixed_payload_len = 20)]
struct CfgPrtUart {
    #[ubx(map_type = UartPortId, may_fail)]
    portid: u8,
    reserved0: u8,
    tx_ready: u16,
    mode: u32,
    baud_rate: u32,
    in_proto_mask: u16,
    out_proto_mask: u16,
    flags: u16,
    reserved5: u16,
}

/// Port Identifier Number (= 1 or 2 for UART ports)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum UartPortId {
    Uart1 = 1,
    Uart2 = 2,
}

/// Port Configuration for SPI Port
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x00,
    fixed_payload_len = 20,
    flags = "default_for_builder"
)]
struct CfgPrtSpi {
    #[ubx(map_type = SpiPortId, may_fail)]
    portid: u8,
    reserved0: u8,
    /// TX ready PIN configuration
    tx_ready: u16,
    /// SPI Mode Flags
    mode: u32,
    reserved3: u32,
    #[ubx(map_type = InProtoMask)]
    in_proto_mask: u16,
    #[ubx(map_type = OutProtoMask)]
    out_proto_mask: u16,
    flags: u16,
    reserved5: u16,
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// A mask describing which input protocolsare active
    /// Each bit of this mask is used for aprotocol.
    /// Through that, multiple protocols can be defined on a single port
    /// Used in `CfgPrtSpi`
    #[derive(Default)]
    pub struct InProtoMask: u16 {
        const UBOX = 1;
        const NMEA = 2;
        const RTCM = 4;
        /// The bitfield inRtcm3 is not supported in protocol
        /// versions less than 20
        const RTCM3 = 0x20;
    }
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// A mask describing which output protocols are active.
    /// Each bit of this mask is used for aprotocol.
    /// Through that, multiple protocols can be defined on a single port
    /// Used in `CfgPrtSpi`
    #[derive(Default)]
    pub struct OutProtoMask: u16 {
        const UBOX = 1;
        const NMEA = 2;
        /// The bitfield outRtcm3 is not supported in protocol
        /// versions less than 20
        const RTCM3 = 0x20;
    }
}

/// Port Identifier Number (= 4 for SPI port)
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum SpiPortId {
    Spi = 4,
}

impl Default for SpiPortId {
    fn default() -> Self {
        Self::Spi
    }
}

/// UTC Time Solution
#[ubx_packet_recv]
#[ubx(class = 1, id = 0x21, fixed_payload_len = 20)]
struct NavTimeUTC {
    /// GPS Millisecond Time of Week
    itow: u32,
    time_accuracy_estimate_ns: u32,

    /// Nanoseconds of second, range -1e9 .. 1e9
    nanos: i32,

    /// Year, range 1999..2099
    year: u16,

    /// Month, range 1..12
    month: u8,

    /// Day of Month, range 1..31
    day: u8,

    /// Hour of Day, range 0..23
    hour: u8,

    /// Minute of Hour, range 0..59
    min: u8,

    /// Seconds of Minute, range 0..59
    sec: u8,

    /// Validity Flags
    #[ubx(map_type = NavTimeUtcFlags)]
    valid: u8,
}

#[ubx_extend_bitflags]
#[ubx(from, rest_reserved)]
bitflags! {
    /// Validity Flags of `NavTimeUTC`
    pub struct NavTimeUtcFlags: u8 {
        /// Valid Time of Week
        const VALID_TOW = 1;
        /// Valid Week Number
        const VALID_WKN = 2;
        /// Valid UTC (Leap Seconds already known)
        const VALID_UTC = 4;
    }
}

/// Navigation/Measurement Rate Settings
#[ubx_packet_send]
#[ubx(class = 6, id = 8, fixed_payload_len = 6)]
struct CfgRate {
    /// Measurement Rate, GPS measurements are taken every `measure_rate_ms` milliseconds
    measure_rate_ms: u16,

    /// Navigation Rate, in number of measurement cycles.

    /// On u-blox 5 and u-blox 6, this parametercannot be changed, and is always equals 1.
    nav_rate: u16,

    /// Alignment to reference time
    #[ubx(map_type = AlignmentToReferenceTime)]
    time_ref: u16,
}

/// Alignment to reference time
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum AlignmentToReferenceTime {
    Utc = 0,
    Gps = 1,
}

impl AlignmentToReferenceTime {
    const fn into_raw(self) -> u16 {
        self as u16
    }
}

/// Set Message Rate the current port
#[ubx_packet_send]
#[ubx(class = 6, id = 1, fixed_payload_len = 3)]
struct CfgMsgSinglePort {
    msg_class: u8,
    msg_id: u8,

    /// Send rate on current Target
    rate: u8,
}

impl CfgMsgSinglePortBuilder {
    #[inline]
    pub fn set_rate_for<T: UbxPacketMeta>(rate: u8) -> Self {
        Self {
            msg_class: T::CLASS,
            msg_id: T::ID,
            rate,
        }
    }
}

/// Set Message rate configuration
/// Send rate is relative to the event a message is registered on.
/// For example, if the rate of a navigation message is set to 2,
/// the message is sent every second navigation solution
#[ubx_packet_send]
#[ubx(class = 6, id = 1, fixed_payload_len = 8)]
struct CfgMsgAllPorts {
    msg_class: u8,
    msg_id: u8,

    /// Send rate on I/O Port (6 Ports)
    rates: [u8; 6],
}

impl CfgMsgAllPortsBuilder {
    #[inline]
    pub fn set_rate_for<T: UbxPacketMeta>(rates: [u8; 6]) -> Self {
        Self {
            msg_class: T::CLASS,
            msg_id: T::ID,
            rates,
        }
    }
}

/// Navigation Engine Settings
#[ubx_packet_recv_send]
#[ubx(
    class = 0x06,
    id = 0x24,
    fixed_payload_len = 36,
    flags = "default_for_builder"
)]
struct CfgNav5 {
    /// Only the masked parameters will be applied
    #[ubx(map_type = CfgNav5Params)]
    mask: u16,
    #[ubx(map_type = CfgNav5DynModel, may_fail)]
    dyn_model: u8,
    #[ubx(map_type = CfgNav5FixMode, may_fail)]
    fix_mode: u8,

    /// Fixed altitude (mean sea level) for 2D fixmode (m)
    #[ubx(map_type = f64, scale = 0.01)]
    fixed_alt: i32,

    /// Fixed altitude variance for 2D mode (m^2)
    #[ubx(map_type = f64, scale = 0.0001)]
    fixed_alt_var: u32,

    /// Minimum Elevation for a GNSS satellite to be used in NAV (deg)
    min_elev_degrees: i8,

    /// Reserved
    dr_limit: u8,

    /// Position DOP Mask to use
    #[ubx(map_type = f32, scale = 0.1)]
    pdop: u16,

    /// Time DOP Mask to use
    #[ubx(map_type = f32, scale = 0.1)]
    tdop: u16,

    /// Position Accuracy Mask (m)
    pacc: u16,

    /// Time Accuracy Mask
    /// according to manual unit is "m", but this looks like typo
    tacc: u16,

    /// Static hold threshold
    #[ubx(map_type = f32, scale = 0.01)]
    static_hold_thresh: u8,

    /// DGNSS timeout (seconds)
    dgps_time_out: u8,

    /// Number of satellites required to have
    /// C/N0 above `cno_thresh` for a fix to be attempted
    cno_thresh_num_svs: u8,

    /// C/N0 threshold for deciding whether toattempt a fix (dBHz)
    cno_thresh: u8,
    reserved1: [u8; 2],

    /// Static hold distance threshold (beforequitting static hold)
    static_hold_max_dist: u16,

    /// UTC standard to be used
    #[ubx(map_type = CfgNav5UtcStandard, may_fail)]
    utc_standard: u8,
    reserved2: [u8; 5],
}

#[ubx_extend_bitflags]
#[ubx(from, into_raw, rest_reserved)]
bitflags! {
    /// `CfgNav5` parameters bitmask
    #[derive(Default)]
    pub struct CfgNav5Params: u16 {
        /// Apply dynamic model settings
        const DYN = 1;
        /// Apply minimum elevation settings
        const MIN_EL = 2;
        /// Apply fix mode settings
       const POS_FIX_MODE = 4;
        /// Reserved
        const DR_LIM = 8;
        /// position mask settings
       const POS_MASK_APPLY = 0x10;
        /// Apply time mask settings
        const TIME_MASK = 0x20;
        /// Apply static hold settings
        const STATIC_HOLD_MASK = 0x40;
        /// Apply DGPS settings
        const DGPS_MASK = 0x80;
        /// Apply CNO threshold settings (cnoThresh, cnoThreshNumSVs)
        const CNO_THRESHOLD = 0x100;
        /// Apply UTC settings (not supported in protocol versions less than 16)
        const UTC = 0x400;
    }
}

/// Dynamic platform model
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum CfgNav5DynModel {
    Portable = 0,
    Stationary = 2,
    Pedestrian = 3,
    Automotive = 4,
    Sea = 5,
    AirborneWithLess1gAcceleration = 6,
    AirborneWithLess2gAcceleration = 7,
    AirborneWith4gAcceleration = 8,
    /// not supported in protocol versions less than 18
    WristWornWatch = 9,
    /// supported in protocol versions 19.2
    Bike = 10,
}

impl Default for CfgNav5DynModel {
    fn default() -> Self {
        Self::AirborneWith4gAcceleration
    }
}

/// Position Fixing Mode
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum CfgNav5FixMode {
    Only2D = 1,
    Only3D = 2,
    Auto2D3D = 3,
}

impl Default for CfgNav5FixMode {
    fn default() -> Self {
        CfgNav5FixMode::Auto2D3D
    }
}

/// UTC standard to be used
#[ubx_extend]
#[ubx(from_unchecked, into_raw, rest_error)]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum CfgNav5UtcStandard {
    /// receiver selects based on GNSS configuration (see GNSS timebases)
    Automatic = 0,
    /// UTC as operated by the U.S. NavalObservatory (USNO);
    /// derived from GPStime
    Usno = 3,
    /// UTC as operated by the former Soviet Union; derived from GLONASS time
    UtcSu = 6,
    /// UTC as operated by the National TimeService Center, China;
    /// derived from BeiDou time
    UtcChina = 7,
}

impl Default for CfgNav5UtcStandard {
    fn default() -> Self {
        Self::Automatic
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ScaleBack<T: FloatCore + FromPrimitive + ToPrimitive>(T);

impl<T: FloatCore + FromPrimitive + ToPrimitive> ScaleBack<T> {
    fn as_i32(self, x: T) -> i32 {
        let x = (x * self.0).round();
        if x < T::from_i32(i32::min_value()).unwrap() {
            i32::min_value()
        } else if x > T::from_i32(i32::max_value()).unwrap() {
            i32::max_value()
        } else {
            x.to_i32().unwrap()
        }
    }

    fn as_u32(self, x: T) -> u32 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u32(u32::max_value()).unwrap() {
                x.to_u32().unwrap()
            } else {
                u32::max_value()
            }
        } else {
            0
        }
    }

    fn as_u16(self, x: T) -> u16 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u16(u16::max_value()).unwrap() {
                x.to_u16().unwrap()
            } else {
                u16::max_value()
            }
        } else {
            0
        }
    }

    fn as_u8(self, x: T) -> u8 {
        let x = (x * self.0).round();
        if !x.is_sign_negative() {
            if x <= T::from_u8(u8::max_value()).unwrap() {
                x.to_u8().unwrap()
            } else {
                u8::max_value()
            }
        } else {
            0
        }
    }
}

/// Receiver/Software Version
#[ubx_packet_recv]
#[ubx(class = 0x13, id = 0x80, max_payload_len = 164)]
struct MgaDbd {
    #[ubx(map_type = Vec<u8>, from = mga_dbd::convert_to_payload)]
    data: [u8; 0],
}

mod mga_dbd {
    pub(crate) fn convert_to_payload(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }
}

pub struct SerializingIterator<T, U>(T)
where
    T: Iterator<Item = U> + Clone,
    U: serde::Serialize + Debug;

impl<T, U> serde::Serialize for SerializingIterator<T, U>
where
    T: Iterator<Item = U> + Clone,
    U: serde::Serialize + Debug,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.clone())
    }
}

impl<T, U> Iterator for SerializingIterator<T, U>
where
    T: Iterator<Item = U> + Clone,
    U: serde::Serialize + Debug,
{
    type Item = U;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<T, U> fmt::Debug for SerializingIterator<T, U>
where
    T: Iterator<Item = U> + Clone,
    U: serde::Serialize + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.clone()).finish()
    }
}

/// Receiver/Software Version
#[ubx_packet_recv]
#[ubx(class = 0x0a, id = 0x04, max_payload_len = 1240)]
struct MonVer {
    #[ubx(map_type = &str, may_fail, from = mon_ver::convert_to_str_unchecked,
          is_valid = mon_ver::is_cstr_valid, get_as_ref)]
    software_version: [u8; 30],
    #[ubx(map_type = &str, may_fail, from = mon_ver::convert_to_str_unchecked,
          is_valid = mon_ver::is_cstr_valid, get_as_ref)]
    hardware_version: [u8; 10],

    /// Extended software information strings
    #[ubx(map_type = SerializingIterator<impl Iterator<Item = &str> + Clone, &str>, may_fail,
          from = mon_ver::extension_to_iter,
          is_valid = mon_ver::is_extension_valid)]
    extension: [u8; 0],
}

mod mon_ver {
    use super::SerializingIterator;

    pub(crate) fn convert_to_str_unchecked(bytes: &[u8]) -> &str {
        let null_pos = bytes
            .iter()
            .position(|x| *x == 0)
            .expect("is_cstr_valid bug?");
        core::str::from_utf8(&bytes[0..=null_pos])
            .expect("is_cstr_valid should have prevented this code from running")
    }

    pub(crate) fn is_cstr_valid(bytes: &[u8]) -> bool {
        let null_pos = match bytes.iter().position(|x| *x == 0) {
            Some(pos) => pos,
            None => {
                return false;
            }
        };
        core::str::from_utf8(&bytes[0..=null_pos]).is_ok()
    }

    pub(crate) fn is_extension_valid(payload: &[u8]) -> bool {
        if payload.len() % 30 == 0 {
            for chunk in payload.chunks(30) {
                if !is_cstr_valid(chunk) {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    pub(crate) fn extension_to_iter(
        payload: &[u8],
    ) -> SerializingIterator<impl Iterator<Item = &str> + Clone, &str> {
        SerializingIterator(payload.chunks(30).map(|x| convert_to_str_unchecked(x)))
    }
}

define_recv_packets!(
    enum PacketRef {
        _ = UbxUnknownPacketRef,
        NavPosEcef,
        NavVelEcef,
        NavPosLlh,
        NavStatus,
        NavAopStatus,
        NavDop,
        NavTimeGps,
        NavPosVelTime,
        NavSolution,
        NavVelNed,
        NavTimeUTC,
        NavTimeLs,
        NavSvInfo,
        NavSbas,
        NavSat,
        AlpSrv,
        AckAck,
        AckNak,
        CfgPrtSpi,
        CfgPrtUart,
        CfgNav5,
        MonVer,
        MgaDbd,
        MgaAck,
    }
);
