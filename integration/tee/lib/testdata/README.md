# Real event logs (`measure.py selftest`)

Each `<name>.json` describes one event log, `<name>.eventlog`, together with the measurements of
the image that produced it.

- **`gce-c3-tdx-20261110`.** The CCEL event log of a GCE C3 TDX VM in europe-west4-a, recorded
  2026-11-10 in measure mode. The VM booted the release image of run `20261110T172647Z`. That
  image had the UKI as `BOOTX64.EFI` and no GRUB. Google's verifier refused the image's token
  because the log had no GRUB measurements.

  The selftest checks two things on this log:
  - `grub_rule` gives the same verdict as Google;
  - the predicted events of RTMR1 and RTMR2 match the log. The prediction comes from the image's
    GPT event, the Authenticode digests of the UKI and the kernel, and the digests of the stub's
    sections.
