//! Time of one `commonware-storage` `Metadata::sync` against the size of the store, on the disk of
//! `DIR`: a sync that adds a key (a full rewrite) and one that overwrites a value of the same size
//! (in place). The signer's state and secret stores are such `Metadata` stores
//! (docs/load-test.md, section 4.1).
//!
//!   cargo run --release --example metadata-sync -- DIR [VALUE_BYTES]

use commonware_runtime::{Runner as _, tokio};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::U64;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("DIR"));
    let value_bytes: usize = args
        .next()
        .map_or(1000, |v| v.parse().expect("VALUE_BYTES"));
    let runtime = tokio::Runner::new(tokio::Config::new().with_storage_directory(&dir));
    runtime.start(|context| async move {
        let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
            context,
            Config {
                partition: "bench".into(),
                codec_config: ((..).into(), ()),
            },
        )
        .await
        .unwrap();
        let value = vec![7u8; value_bytes];
        let mut next = 0u64;
        println!("entries  MB     add_key_ms  overwrite_ms");
        for target in [0u64, 500, 1000, 2000, 4000, 8000, 16000] {
            while next < target {
                metadata.put(U64::new(next), value.clone());
                next += 1;
            }
            metadata = metadata.sync().await.unwrap();
            let mut add = Vec::new();
            let mut overwrite = Vec::new();
            for _ in 0..10 {
                metadata.put(U64::new(next), value.clone());
                next += 1;
                let start = Instant::now();
                metadata = metadata.sync().await.unwrap();
                add.push(start.elapsed().as_secs_f64() * 1e3);
                let mut changed = value.clone();
                changed[0] = (next % 251) as u8;
                metadata.put(U64::new(next - 1), changed);
                let start = Instant::now();
                metadata = metadata.sync().await.unwrap();
                overwrite.push(start.elapsed().as_secs_f64() * 1e3);
            }
            add.sort_by(f64::total_cmp);
            overwrite.sort_by(f64::total_cmp);
            println!(
                "{next:7}  {:5.1}  {:10.2}  {:12.2}",
                (next as usize * (value_bytes + 8)) as f64 / 1e6,
                add[5],
                overwrite[5]
            );
        }
    });
}
