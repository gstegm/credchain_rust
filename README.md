# Pure Rust version of credchain repository

First, the Rust programming language needs to be installed on the system used, which is described [here](https://www.rust-lang.org/tools/install).
Then, the project can be built via
```shell
cargo build --release
```
and the performance measurement executed with
```shell
cargo run --release
```

# References 
- [TFHE-rs](https://github.com/zama-ai/tfhe-rs) library for Homomorphic Encryption in Rust, based on the TFHE encryption scheme. Read the documentation [here](https://docs.zama.ai/tfhe-rs).