//! `tee-fake-gcp`: the fake of Google's attestation, STS and KMS (`attestation::fake`) as a
//! service, for sealed nodes in VMs under QEMU (`integration/tee`). Tests only: built with
//! `test-hooks`, never deployed.
//!
//! It writes, into `--out`:
//! - `policy.json` and `jwks.json`, for `mpc-admin attest` and `mpc-keytool split`;
//! - `node-<i>.args`: node `i`'s vault flags, one per line, as the VM reaches this service at
//!   `--vm-url`.
//!
//! It then serves until killed. `POST /control/vm/mpc-tee-<i>` with `{"rtmr1", "rtmr2",
//! "dbgstat"}` changes what VM `i` reports from then on (another image, a debug VM).

use clap::Parser;
use eth_mpc_signer::attestation::fake::{FakeGcp, instance};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "A fake of Google's attestation, STS and KMS, for tests of sealed nodes")]
struct Args {
    /// Address to serve on.
    #[arg(long)]
    listen: SocketAddr,
    /// Number of VMs (`mpc-tee-0` ..).
    #[arg(long, default_value_t = 4)]
    vms: usize,
    /// The URL VMs reach this service at (for QEMU's user network: `http://10.0.2.2:<port>`).
    #[arg(long)]
    vm_url: String,
    /// Directory for `policy.json`, `jwks.json` and `node-<i>.args` (created if missing).
    #[arg(long)]
    out: PathBuf,
}

fn main() {
    let args = Args::parse();
    let fake = FakeGcp::start_on(args.listen, args.vms);
    std::fs::create_dir_all(&args.out).expect("output directory");
    let write = |name: &str, text: String| {
        std::fs::write(args.out.join(name), text)
            .unwrap_or_else(|err| panic!("{}: {err}", args.out.join(name).display()));
    };
    write(
        "policy.json",
        serde_json::to_string_pretty(&fake.policy()).expect("serializable"),
    );
    write(
        "jwks.json",
        serde_json::to_string_pretty(&fake.jwks()).expect("serializable"),
    );
    for id in 0..args.vms {
        let flags = fake.vault_args_at(id, &instance(id), args.vm_url.trim_end_matches('/'));
        write(&format!("node-{id}.args"), flags.join("\n") + "\n");
    }
    eprintln!(
        "tee-fake-gcp: serving {} on {} for {} VMs (they reach it at {}); files in {}",
        fake.url,
        args.listen,
        args.vms,
        args.vm_url,
        args.out.display()
    );
    loop {
        std::thread::park();
    }
}
