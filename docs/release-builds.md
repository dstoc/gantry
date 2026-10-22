# Release Build Configuration and Sizes

## Build configuration

The release workflow builds `gantry`, `gantry-supervisor`, and `run-remote` with:

```sh
cargo build --locked --release --bins --target <target>
```

The release profile sets `strip = "symbols"`. Cargo keeps its other release defaults. In particular, the profile keeps optimization level 3, 16 codegen units, no LTO, and the default unwind panic strategy.

Stripping removes symbol information from the packaged executables. It does not change generated machine code or runtime behavior. It adds a strip pass to the release build. The release workflow does not package separate debug symbols. For a symbolized release build, use:

```sh
CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --locked --release --bins
```

The native matrix's build-and-package step took 174 seconds before and 171 seconds after on Linux x86_64, 119 and 126 seconds on Linux aarch64, and 223 and 220 seconds on Darwin aarch64. These times include compilation, smoke checks, archive creation, and measurement. They show no consistent build-time increase. On local Linux x86_64, `readelf -d` showed the same `NEEDED` entries before and after: `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, and `ld-linux-x86-64.so.2`. The target triples and linker settings did not change.

Local Linux x86_64 experiments used Rust 1.98.1. Thin LTO was tested with symbol stripping. It increased the combined executable size from 23,126,200 to 26,364,672 bytes, so the release profile does not enable LTO. Changing `tokio/full` to a narrower feature list saved 72 bytes across the three local x86_64 executables. That change also removed an optional `parking_lot` dependency, so the existing Tokio feature selection remains unchanged.

## Measurement method

The release build workflow runs the same build, architecture checks, smoke checks, packaging, and archive validation for each target. It reports sizes from the final validated archive. Binary sizes come from the archive members. Archive sizes come from the complete `.tar.gz` file that the job uploads.

The workflow summary and check annotations include the build source commit and Rust compiler version. The source ref can be selected with the `source_ref` input when a maintainer dispatches `Release build verification`. The native runners are `ubuntu-22.04` for Linux x86_64, `ubuntu-22.04-arm` for Linux aarch64, and `macos-15` for Darwin aarch64.

The baseline rebuild uses tag `v0.4.8` at commit `fa9b85737c4aab055486c23f7fa7d12f4c76e06a`, before the release profile setting. The optimized build uses commit `e41a5b342c4fce0e621422eaccec9e27e5fb2cba`. Both use Rust 1.99.1, the same locked release command, and the same native runner matrix. All six native build jobs passed their architecture checks, binary smoke checks, packaging, and archive validation. The build reports are in [release build verification run 39766740187](https://github.com/dstoc/gantry/actions/runs/39766740187).

## Before and after sizes

All sizes are bytes. A negative percentage means the optimized artifact is smaller.

Across the three targets, executable bytes fell 25.1%, from 82,926,136 to 62,080,976. Archive bytes fell 12.7%, from 27,692,811 to 24,178,348.

| Target | Artifact | Baseline | Optimized | Change |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | `gantry` | 19,101,952 | 14,214,800 | -25.6% |
| Linux x86_64 | `gantry-supervisor` | 1,614,544 | 1,098,520 | -32.0% |
| Linux x86_64 | `run-remote` | 10,063,128 | 7,747,048 | -23.0% |
| Linux x86_64 | Executable total | 30,779,624 | 23,060,368 | -25.1% |
| Linux x86_64 | Archive | 9,850,225 | 8,727,558 | -11.4% |
| Linux aarch64 | `gantry` | 18,130,016 | 12,897,456 | -28.9% |
| Linux aarch64 | `gantry-supervisor` | 1,629,024 | 1,045,520 | -35.8% |
| Linux aarch64 | `run-remote` | 8,126,736 | 5,912,704 | -27.2% |
| Linux aarch64 | Executable total | 27,885,776 | 19,855,680 | -28.8% |
| Linux aarch64 | Archive | 9,308,106 | 7,766,166 | -16.6% |
| Darwin aarch64 | `gantry` | 15,465,872 | 12,115,312 | -21.7% |
| Darwin aarch64 | `gantry-supervisor` | 1,431,456 | 1,052,720 | -26.5% |
| Darwin aarch64 | `run-remote` | 7,363,408 | 5,996,896 | -18.6% |
| Darwin aarch64 | Executable total | 24,260,736 | 19,164,928 | -21.0% |
| Darwin aarch64 | Archive | 8,534,480 | 7,684,624 | -10.0% |

The existing `v0.4.8` downloadable archives had these byte sizes:

| Target | Published archive bytes |
| --- | ---: |
| Linux x86_64 | 9,850,319 |
| Linux aarch64 | 9,308,059 |
| Darwin aarch64 | 8,534,468 |

GitHub reported these sizes for the published release assets.

The release workflow downloads the validated build archives and creates `SHA256SUMS` from those bytes. It verifies the checksum set and archive contents before upload. It then downloads and verifies the uploaded assets before it publishes the release. The size report runs after archive validation and does not change that order.
