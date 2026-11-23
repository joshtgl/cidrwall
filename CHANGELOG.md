# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/joshtgl/cidrwall/compare/v0.1.3...v0.2.0) - 2026-11-23

### Added

- write an optional JSON status file
- retry metrics binds in the background and accept multiple addresses
- add Prometheus /metrics endpoint
- [**breaking**] add TCX egress destination CIDR enforcement with atomic reloads and flowtable safety checks

### Fixed

- *(deps)* update rust crate clap to 4.6.9 ([#22](https://github.com/joshtgl/cidrwall/pull/22))
- replace the XDP program on existing links at startup
- migrate to aya 0.16 API
- *(deps)* update rust dependencies
- *(deps)* update rust dependencies ([#8](https://github.com/joshtgl/cidrwall/pull/8))
- *(deps)* update rust dependencies

### Other

- deny panicking constructs in clippy and run clippy in CI
- read eBPF toolchain pin from a single file and fix semver baseline
- *(deps)* lock file maintenance cargo.lock
- *(deps)* update dependency bpf-linker to v0.13.0
- pin eBPF nightly toolchain and update bpf-linker to 0.11.1
- remove publishing section

## [0.1.3](https://github.com/joshtgl/cidrwall/compare/v0.1.2...v0.1.3) - 2026-09-05

### Added

- verify after applying lists, apply sets separately
- add additional logging messages

### Fixed

- move logs to debug
- set count constant
- update default batch sizes

### Other

- *(ci)* push dev version image

## [0.1.2](https://github.com/joshtgl/cidrwall/compare/v0.1.1...v0.1.2) - 2026-08-21

### Added

- stream lists, assume ordered

## [0.1.1](https://github.com/joshtgl/cidrwall/compare/v0.1.0...v0.1.1) - 2026-08-21

### Fixed

- *(deps)* update rust crate toml to v1

### Other

- *(deps)* update rust docker tag to v1.97
- *(ci)* add release workflows
