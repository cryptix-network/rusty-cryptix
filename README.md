# Cryptix Rust Node

This repository contains the Rust implementation of the Cryptix full node and related libraries.
The goal is simple: a production-ready node that stays compatible with the existing Cryptix network and can replace the legacy Golang daemon in day-to-day operation.
If you prefer the previous implementation, the <a href="https://github.com/cryptix-network/cryptixd">Golang node</a> remains available as an alternative.

If you run infrastructure, build tooling, or contribute code, this repo is the main place to work on the Rust node stack.
Feedback and contributions are always welcome.

## Node Startup Arguments (`cryptixd`)


| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-C`, `--configfile=<CONFIG_FILE>` | path | none | Load settings from a TOML config file. |
| `-b`, `--appdir=<DATA_DIR>` | path | none | Base data directory. |
| `--logdir=<LOG_DIR>` | path | none | Log file directory. |
| `--nologfiles` | switch | `false` | Disable logging to files. |
| `-t`, `--async-threads=<N>` | integer | CPU core count | Number of async runtime threads. |
| `-d`, `--loglevel=<LEVEL>` | string | `info` | Global/per-subsystem log level. |
| `--rpclisten[=IP[:PORT]]` | address | auto | gRPC listen address (defaults to network-specific port). |
| `--rpclisten-borsh[=IP[:PORT]]` | address | auto | wRPC Borsh listen address (defaults to network-specific port). |
| `--rpclisten-json[=IP[:PORT]]` | address | auto | wRPC JSON listen address (defaults to network-specific port). |
| `--unsaferpc` | switch | `false` | Enable RPC commands that mutate node state. |
| `--connect=<IP[:PORT]>` | address (repeatable) | empty | Connect only to specified peers. |
| `--addpeer=<IP[:PORT]>` | address (repeatable) | empty | Add peers to connect to on startup. |
| `--listen=<IP[:PORT]>` | address | auto | P2P listen address (defaults to network-specific port). |
| `--outpeers=<N>` | integer | `8` | Target outbound peer count. |
| `--maxinpeers=<N>` | integer | `128` | Maximum inbound peer count. |
| `--rpcmaxclients=<N>` | integer | `128` | Maximum standard RPC clients. |
| `--reset-db` | switch | `false` | Reset local database before startup. |
| `--enable-unsynced-mining` | switch | `false` | Accept RPC block submits while unsynced (testing-oriented). |
| `--enable-mainnet-mining` | switch | `true` (deprecated flag) | Backward-compatible flag; mainnet mining is enabled by default. |
| `--utxoindex` | switch | `false` | Enable UTXO index. |
| `--max-tracked-addresses=<N>` | integer | `0` | Preallocated max addresses for UTXO change tracking. |
| `--testnet` | switch | `false` | Use testnet. |
| `--netsuffix=<N>` | integer | none | Optional testnet suffix (for dedicated parallel testnet variants). |
| `--devnet` | switch | `false` | Use devnet. |
| `--simnet` | switch | `false` | Use simnet. |
| `--archival` | switch | `false` | Run in archival mode (increased disk usage). |
| `--sanity` | switch | `false` | Enable additional sanity checks. |
| `--yes` | switch | `false` | Auto-confirm interactive prompts. |
| `--uacomment=<TEXT>` | string (repeatable) | empty | Append user-agent comments. |
| `--externalip=<IP[:PORT]>` | address | none | Advertised external P2P address. |
| `--perf-metrics` | switch | `false` | Enable runtime perf metrics collection. |
| `--perf-metrics-interval-sec=<SECONDS>` | integer | `10` | Perf metrics collection interval. |
| `--tx-relay-broadcast-interval-ms=<MS>` | integer | `250` | Interval in milliseconds for batching mempool transaction INV broadcasts. |
| `--datacenter` | switch | `false` | Enable datacenter peer filter mode (skip private/unroutable peer addresses in address manager). |
| `--hfa` | switch | `false` | Enable HFA fast rail for this process. |
| `--hfa-cpu=<RATIO>` | float | `0.7` | HFA CPU low-water ratio (`0.0 < value <= 1.0`). |
| `--hfa-drift-ms=<MS>` | integer | `5000` | HFA clock drift window in milliseconds for fast-intent admission. |
| `--hfa-microblock-interval-ms-normal=<MS>` | integer | `50` | HFA microblock interval in milliseconds while in normal mode. |
| `--no-hfa` | switch | `false` | Force-disable HFA (overrides config). |
| `--strong-nodes` | switch | `true` | Enable optional Strong-Nodes overlay (Discovery/Hint, non-consensus). |
| `--no-strong-nodes` | switch | `false` | Disable Strong-Nodes overlay locally (overrides config). |
| `--autoban` | switch | `true` | Enable automatic banning of repeatedly misbehaving peers. |
| `--no-autoban` | switch | `false` | Disable automatic banning of repeatedly misbehaving peers (overrides config). |
| `--banserver` | switch | `true` | Enable remote ban list synchronization from the antifraud banserver. |
| `--no-banserver` | switch | `false` | Disable remote ban list synchronization from the antifraud banserver (overrides config). |
| `--banserver-url=<URL>` | string | `https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot` | Override the banserver endpoint for remote IP blocklist sync. |
| `--disable-upnp` | switch | `false` | Disable UPnP. |
| `--nodnsseed` | switch | `false` | Disable DNS peer seeding. |
| `--nogrpc` | switch | `false` | Disable gRPC server. |
| `--ram-scale=<FACTOR>` | float | `1.0` | Scale memory-bound internal limits. |
| `--num-prealloc-utxos=<N>` | integer | none | Devnet preallocation count (`devnet-prealloc` feature only). |
| `--prealloc-address=<ADDR>` | string | none | Devnet preallocation target address (`devnet-prealloc` feature only). |
| `--prealloc-amount=<SOMPI>` | integer | `10000000000` | Devnet preallocation amount per UTXO (`devnet-prealloc` feature only). |

## Installation
  <details>
  <summary>Building on Linux</summary>

  1. Install general prerequisites

      ```bash
      sudo apt install curl git build-essential libssl-dev pkg-config
      ```

  2. Install Protobuf (required for gRPC)

      ```bash
      sudo apt install protobuf-compiler libprotobuf-dev #Required for gRPC
      ```
  3. Install the clang toolchain (required for RocksDB and WASM secp256k1 builds)

      ```bash
      sudo apt-get install clang-format clang-tidy \
      clang-tools clang clangd libc++-dev \
      libc++1 libc++abi-dev libc++abi1 \
      libclang-dev libclang1 liblldb-dev \
      libllvm-ocaml-dev libomp-dev libomp5 \
      lld lldb llvm-dev llvm-runtime \
      llvm python3-clang
      ```
  3. Install the [rust toolchain](https://rustup.rs/)

     If you already have rust installed, update it by running: `rustup update`
  4. Install wasm-pack
      ```bash
      cargo install wasm-pack
      ```
  4. Install wasm32 target
      ```bash
      rustup target add wasm32-unknown-unknown
      ```
  5. Clone the repo
      ```bash
      git clone https://github.com/cryptix-network/rusty-cryptix
      cd rusty-cryptix
      ```
  </details>



  <details>
  <summary>Building on Windows</summary>


  1. [Install Git for Windows](https://gitforwindows.org/) or an alternative Git distribution.

  2. Install [Protocol Buffers](https://github.com/protocolbuffers/protobuf/releases/download/v21.10/protoc-21.10-win64.zip) and add the `bin` directory to your `Path`


3. Install [LLVM-15.0.6-win64.exe](https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.6/LLVM-15.0.6-win64.exe)

    Add the `bin` directory of the LLVM installation (`C:\Program Files\LLVM\bin`) to PATH

    set `LIBCLANG_PATH` environment variable to point to the `bin` directory as well

    **IMPORTANT:** Due to C++ dependency configuration issues, LLVM `AR` installation on Windows may not function correctly when switching between WASM and native C++ code compilation (native `RocksDB+secp256k1` vs WASM32 builds of `secp256k1`). Unfortunately, manually setting `AR` environment variable also confuses C++ build toolchain (it should not be set for native but should be set for WASM32 targets). Currently, the best way to address this, is as follows: after installing LLVM on Windows, go to the target `bin` installation directory and copy or rename `LLVM_AR.exe` to `AR.exe`.

  4. Install the [rust toolchain](https://rustup.rs/)

     If you already have rust installed, update it by running: `rustup update`
  5. Install wasm-pack
      ```bash
      cargo install wasm-pack
      ```
  6. Install wasm32 target
      ```bash
      rustup target add wasm32-unknown-unknown
      ```
  7. Clone the repo
      ```bash
      git clone https://github.com/cryptix-network/rusty-cryptix
      cd rusty-cryptix
      cargo build --release --bin cryptixd 
      ```
 </details>


  <details>
  <summary>Building on Mac OS</summary>


  1. Install Protobuf (required for gRPC)
      ```bash
      brew install protobuf
      ```
  2. Install llvm.

      The default XCode installation of `llvm` does not support WASM build targets.
To build WASM on MacOS you need to install `llvm` from homebrew (at the time of writing, the llvm version for MacOS is 16.0.1).
      ```bash
      brew install llvm
      ```

      **NOTE:** Homebrew can use different keg installation locations depending on your configuration. For example:
      - `/opt/homebrew/opt/llvm` -> `/opt/homebrew/Cellar/llvm/16.0.1`
      - `/usr/local/Cellar/llvm/16.0.1`

      To determine the installation location you can use `brew list llvm` command and then modify the paths below accordingly:
      ```bash
      % brew list llvm
      /usr/local/Cellar/llvm/16.0.1/bin/FileCheck
      /usr/local/Cellar/llvm/16.0.1/bin/UnicodeNameMappingGenerator
      ...
      ```
      If you have `/opt/homebrew/Cellar`, then you should be able to use `/opt/homebrew/opt/llvm`.

      Add the following to your `~/.zshrc` file:
      ```bash
      export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
      export LDFLAGS="-L/opt/homebrew/opt/llvm/lib"
      export CPPFLAGS="-I/opt/homebrew/opt/llvm/include"
      export AR=/opt/homebrew/opt/llvm/bin/llvm-ar
      ```

      Reload the `~/.zshrc` file
      ```bash
      source ~/.zshrc
      ```
  3. Install the [rust toolchain](https://rustup.rs/)

     If you already have rust installed, update it by running: `rustup update`
  4. Install wasm-pack
      ```bash
      cargo install wasm-pack
      ```
  4. Install wasm32 target
      ```bash
      rustup target add wasm32-unknown-unknown
      ```
  5. Clone the repo
      ```bash
      git clone https://github.com/cryptix-network/rusty-cryptix
      cd rusty-cryptix
      ```

 </details>

  <details>

  <summary>Building WASM32 SDK</summary>

  Rust WebAssembly (WASM) refers to the use of the Rust programming language to write code that can be compiled into WebAssembly, a binary instruction format that runs in web browsers and NodeJs. This allows for easy development using JavaScript and TypeScript programming languages while retaining the benefits of Rust.

  WASM SDK components can be built from sources by running:
    - `./build-release` - build a full release package (includes both release and debug builds for web and nodejs targets)
    - `./build-docs` - build TypeScript documentation
    - `./build-web` - release web build
    - `./build-web-dev` - development web build
    - `./build-nodejs` - release nodejs build
    - `./build-nodejs-dev` - development nodejs build

  IMPORTANT: do not use `dev` builds in production. They are significantly larger, slower and include debug symbols.

### Requirements

  - NodeJs (v20+): https://nodejs.org/en
  - TypeDoc: https://typedoc.org/

### Builds & documentation

  - Release builds: https://github.com/cryptix-network/rusty-cryptix/releases

  </details>
<details>

<summary>
Cryptix CLI + Wallet
</summary>

`cryptix-cli` crate provides a cli-driven RPC interface to the node and a
terminal interface to the Rusty Cryptix Wallet runtime. These wallets are
compatible with WASM SDK Wallet API and Cryptix NG projects.


```bash
cd cli
cargo run --release
```

</details>



<details>

<summary>
Local Web Wallet
</summary>

Run an http server inside of `wallet/wasm/web` folder. If you don't have once, you can use the following:

```bash
cd wallet/wasm/web
cargo install basic-http-server
basic-http-server
```
The *basic-http-server* will serve on port 4000 by default, so open your web browser and load http://localhost:4000

The framework is compatible with all major desktop and mobile browsers.


</details>


## Running the node

  **Start a mainnet node**

  ```bash
  cargo run --release --bin cryptixd
  # or with UTXO-index enabled (needed when using wallets)
  cargo run --release --bin cryptixd -- --utxoindex
  ```
  **Start a testnet node**

  ```bash
cargo run --release --bin cryptixd -- --testnet
  ```

  Optionally, `--netsuffix=<N>` can be used to run an isolated suffixed testnet id when needed.

<details>

  <summary>
Using a configuration file
  </summary>

  ```bash
cargo run --release --bin cryptixd -- --configfile /path/to/configfile.toml
# or
cargo run --release --bin cryptixd -- -C /path/to/configfile.toml
  ```
  - The config file should be a list of \<CLI argument\> = \<value\> separated by newlines.
  - Whitespace around the `=` is fine, `arg=value` and `arg = value` are both parsed correctly.
  - Values with special characters like `.` or `=` will require quoting the value i.e \<CLI argument\> = "\<value\>".
  - Arguments with multiple values should be surrounded with brackets like `addpeer = ["10.0.0.1", "1.2.3.4"]`.

  For example:
  ```
testnet = true
utxoindex = false
disable-upnp = true
perf-metrics = true
tx-relay-broadcast-interval-ms = 250
appdir = "some-dir"
hfa-microblock-interval-ms-normal = 50
autoban = true
banserver = true
banserver-url = "https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot"
addpeer = ["10.0.0.1", "1.2.3.4"]
  ```
Pass the `--help` flag to view all possible arguments

  ```bash
cargo run --release --bin cryptixd -- --help
  ```

  Auto-ban defaults:
  - enabled by default (`autoban = true`)
  - ban threshold: 5 strikes
  - ban duration: 3 hours
  - inbound connection rate-limiter
  - rate-limit penalties are strike-cooldown limited to 1 per 60s per IP

  Banserver sync defaults:
  - enabled by default (`banserver = true`)
  - startup fetch + periodic refresh every 20 minutes
  - endpoint default: `https://antifraud.cryptix-network.org/api/v1/antifraud/snapshot`
  - fail-open: server/network/payload errors are ignored safely and do not crash node operation
</details>

<details>

  <summary>
wRPC
  </summary>

  wRPC subsystem is disabled by default in `cryptixd` and can be enabled via:


  JSON protocol:
  ```bash
  --rpclisten-json = <interface:port>
  # or use the defaults for current network
  --rpclisten-json = default
  ```

  Borsh protocol:
  ```bash
  --rpclisten-borsh = <interface:port>
  # or use the defaults for current network
  --rpclisten-borsh = default
  ```

  **Sidenote:**

  Rusty Cryptix integrates an optional wRPC
  subsystem. wRPC is a high-performance, platform-neutral, Rust-centric, WebSocket-framed RPC
  implementation that can use [Borsh](https://borsh.io/) and JSON protocol encoding.

  JSON protocol messaging
  is similar to JSON-RPC 1.0, but differs from the specification due to server-side
  notifications.

  [Borsh](https://borsh.io/) encoding is meant for inter-process communication. When using [Borsh](https://borsh.io/)
  both client and server should be built from the same codebase.

  JSON protocol is based on
  Cryptix data structures and is data-structure-version agnostic. You can connect to the
  JSON endpoint using any WebSocket library. Built-in RPC clients for JavaScript and
  TypeScript capable of running in web browsers and Node.js are available as a part of
  the Cryptix WASM framework.

</details>


## Benchmarking & Testing


<details>

<summary>Simulation framework (Simpa)</summary>

The current codebase supports a full in-process network simulation, building an actual DAG over virtual time with virtual delay and benchmarking validation time (following the simulation generation).

To see the available commands
```bash
cargo run --release --bin simpa -- --help
```

The following command will run a simulation to produce 1000 blocks with communication delay of 2 seconds and 8 BPS (blocks per second) while attempting to fill each block with up to 200 transactions.

```bash
cargo run --release --bin simpa -- -t=200 -d=2 -b=8 -n=1000
```

</details>




<details>

<summary>Heap Profiling</summary>

Heap-profiling in `cryptixd` and `simpa` can be done by enabling `heap` feature and profile using the `--features` argument

```bash
cargo run --bin cryptixd --profile heap --features=heap
```

It will produce `{bin-name}-heap.json` file in the root of the workdir, that can be inspected by the [dhat-viewer](https://github.com/unofficial-mirror/valgrind/tree/master/dhat)

</details>


<details>

<summary>Tests</summary>


**Run unit and most integration tests**

```bash
cd rusty-cryptix
cargo test --release
// or install nextest and run
```



**Using nextest**

```bash
cd rusty-cryptix
cargo nextest run --release
```

</details>

<details>

<summary>Lints</summary>

```bash
cd rusty-cryptix
./check
```

</details>


<details>

<summary>Benchmarks</summary>

```bash
cd rusty-cryptix
cargo bench
```

</details>

<details>

<summary>Logging</summary>

Logging in `cryptixd` and `simpa` can be [filtered](https://docs.rs/env_logger/0.10.0/env_logger/#filtering-results) by either:

1. Defining the environment variable `RUST_LOG`
2. Adding the --loglevel argument like in the following example:

    ```
    (cargo run --bin cryptixd -- --loglevel info,cryptix_rpc_core=trace,cryptix_grpc_core=trace,consensus=trace,cryptix_core=trace) 2>&1 | tee ~/rusty-cryptix.log
    ```
    In this command we set the `loglevel` to `INFO`.

</details>




## Discord

Join our discord server using the following link: [https://discord.cryptix-network.org/](https://discord.cryptix-network.org/)
