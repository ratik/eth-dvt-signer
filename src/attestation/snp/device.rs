//! The SEV-SNP guest device (`/dev/sev-guest`, Linux `sev-guest` driver): requests to the AMD
//! secure processor, encrypted between it and the guest, so the host can drop them but not read or
//! change them.
//!
//! - `SNP_GET_REPORT`: an attestation report with the guest's 64 bytes of `REPORT_DATA`.
//! - `SNP_GET_DERIVED_KEY`: a key derived from the chip's VCEK secret and the guest fields the
//!   request selects (the launch measurement, the policy, a TCB version, ...). Only a guest with
//!   these fields, on this chip, gets the same key.
//!
//! The device is root's by default: the image gives it to the node's user.

use zeroize::Zeroizing;

/// `GUEST_FIELD_SELECT` bits of a derived key.
pub mod field {
    pub const POLICY: u64 = 1 << 0;
    pub const IMAGE_ID: u64 = 1 << 1;
    pub const FAMILY_ID: u64 = 1 << 2;
    pub const MEASUREMENT: u64 = 1 << 3;
    pub const GUEST_SVN: u64 = 1 << 4;
    pub const TCB_VERSION: u64 = 1 << 5;
}

/// A derived-key request (root: the VCEK; VMPL 0; guest SVN 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRequest {
    /// `GUEST_FIELD_SELECT` ([field]).
    pub fields: u64,
    /// The TCB version mixed in when `fields` selects it: at most the committed one.
    pub tcb_version: u64,
}

/// The guest's access to its secure processor.
pub trait Device: Send + Sync {
    /// An attestation report (raw, [super::report::SIZE] bytes) with `report_data`, from VMPL 0.
    fn report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, String>;
    /// A key derived for `request`.
    fn derived_key(&self, request: &KeyRequest) -> Result<Zeroizing<[u8; 32]>, String>;
}

/// The default device path.
pub const DEFAULT_PATH: &str = "/dev/sev-guest";

/// The kernel's device.
#[derive(Clone, Debug)]
pub struct GuestDevice {
    path: std::path::PathBuf,
}

impl GuestDevice {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd as _;

    /// `struct snp_guest_request_ioctl`.
    #[repr(C)]
    pub struct Request {
        pub msg_version: u8,
        pub req_data: u64,
        pub resp_data: u64,
        /// `fw_error` (low 32 bits) and `vmm_error` (high).
        pub exitinfo2: u64,
    }

    /// `_IOWR('S', nr, struct snp_guest_request_ioctl)`.
    const fn iowr(nr: u64) -> u64 {
        (3 << 30) | ((size_of::<Request>() as u64) << 16) | ((b'S' as u64) << 8) | nr
    }
    pub const GET_REPORT: u64 = iowr(0);
    pub const GET_DERIVED_KEY: u64 = iowr(1);

    /// Send `request` to the device at `path` with `req` in and `resp` out.
    pub fn call(
        path: &std::path::Path,
        command: u64,
        req: &[u8],
        resp: &mut [u8],
    ) -> Result<(), String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        let mut request = Request {
            msg_version: 1,
            req_data: req.as_ptr() as u64,
            resp_data: resp.as_mut_ptr() as u64,
            exitinfo2: 0,
        };
        // SAFETY: the request points to buffers of the sizes the driver reads and writes (the
        // caller's `req` and `resp` are those structures' sizes), alive during the call.
        let result =
            unsafe { libc::ioctl(file.as_raw_fd(), command as _, &mut request as *mut Request) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!(
                "{}: {err} (firmware error {:#x}, VMM error {:#x})",
                path.display(),
                request.exitinfo2 & 0xFFFF_FFFF,
                request.exitinfo2 >> 32
            ));
        }
        Ok(())
    }
}

/// The status word of a response from the secure processor (0: success).
fn status(response: &[u8]) -> u32 {
    u32::from_le_bytes(response[..4].try_into().expect("4 bytes"))
}

impl Device for GuestDevice {
    #[cfg(target_os = "linux")]
    fn report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
        // `struct snp_report_req`: user data, VMPL, reserved.
        let mut req = [0u8; 96];
        req[..64].copy_from_slice(report_data);
        // `struct snp_report_resp`: MSG_REPORT_RSP (status, size, reserved, report).
        let mut resp = vec![0u8; 4000];
        linux::call(&self.path, linux::GET_REPORT, &req, &mut resp)?;
        if status(&resp) != 0 {
            return Err(format!("SNP_GET_REPORT: status {:#x}", status(&resp)));
        }
        let size = u32::from_le_bytes(resp[4..8].try_into().expect("4 bytes")) as usize;
        if size != super::report::SIZE {
            return Err(format!("SNP_GET_REPORT: a report of {size} bytes"));
        }
        Ok(resp[0x20..0x20 + size].to_vec())
    }

    #[cfg(target_os = "linux")]
    fn derived_key(&self, request: &KeyRequest) -> Result<Zeroizing<[u8; 32]>, String> {
        // `struct snp_derived_key_req`: root key (0: VCEK), reserved, fields, VMPL, guest SVN,
        // TCB version.
        let mut req = [0u8; 32];
        req[8..16].copy_from_slice(&request.fields.to_le_bytes());
        req[24..32].copy_from_slice(&request.tcb_version.to_le_bytes());
        // `struct snp_derived_key_resp`: MSG_KEY_RSP (status, reserved, key).
        let mut resp = Zeroizing::new([0u8; 64]);
        linux::call(
            &self.path,
            linux::GET_DERIVED_KEY,
            &req,
            resp.as_mut_slice(),
        )?;
        if status(resp.as_slice()) != 0 {
            return Err(format!(
                "SNP_GET_DERIVED_KEY: status {:#x}",
                status(resp.as_slice())
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&resp[0x20..0x40]);
        Ok(key)
    }

    #[cfg(not(target_os = "linux"))]
    fn report(&self, _: &[u8; 64]) -> Result<Vec<u8>, String> {
        Err(format!("{}: SEV-SNP guests run Linux", self.path.display()))
    }

    #[cfg(not(target_os = "linux"))]
    fn derived_key(&self, _: &KeyRequest) -> Result<Zeroizing<[u8; 32]>, String> {
        Err(format!("{}: SEV-SNP guests run Linux", self.path.display()))
    }
}
