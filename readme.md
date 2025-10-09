# Qadena

**Qadena** is a privacy-by-design blockchain platform built on the Cosmos SDK that provides secure and confidential capabilities for financial services, government services, and identity management.  It features Confidentiality, Compliance, and built-in credentials.  The platform leverages Intel SGX (Software Guard Extensions) technology to create trusted execution environments (enclaves) that protect sensitive data and computations.

## Key Features

- **Confidential Computing**: Built-in support for Intel SGX enclaves for secure, private transactions
- **Financial Services**: Native support for financial applications with multi-currency price feeds
- **Identity Management**: Decentralized identity services with privacy-preserving credentials
- **Multi-Service Architecture**: Supports various service providers (identity, finance, DSVS)
- **Native Token**: QDN token with built-in incentive mechanisms for wallet creation and usage
- **Cosmos Ecosystem**: Built on Cosmos SDK for interoperability and proven blockchain infrastructure

## Architecture

Qadena operates as a sovereign blockchain with multiple node types:
- **Pioneer Nodes**: Core validator nodes that secure the network

The platform integrates with external price oracles (CoinGecko, Band Protocol) and supports multiple fiat currencies including USD, PHP, and AUD.

## OS

Ubuntu 22.04

---

# Setup

## Get the repository

```bash
git clone https://github.com/c3qtech/qadena_v3.git
```

# Development Setup

## Ubuntu

cd qadena_v3/ubuntu

./setup_qadena_build.sh

## Mac OS X

Note, these might not work exactly, but should give you an idea of what to do.

### 1. Install Go (version 1.23.4)

Visit the official Go installation guide: https://go.dev/doc/install

#### Add Go binary path to PATH
Add the following to your `~/.zshrc` file (modify `/Users/alvillarica` as appropriate for your OS):

```bash
export PATH=$PATH:/Users/alvillarica/go/bin
```

### 2. Install compiler

xcode-select --install

### 3. Install Homebrew

If you're on macOS, you may need to install Homebrew: https://brew.sh/

### 4.  Install Ignite CLI

First, remove any old Ignite versions:
```bash
rm `which ignite`
```

Follow the official installation instructions: https://docs.ignite.com/welcome/install

For Cosmos SDK v0.50.6 compatibility:
```bash
curl https://get.ignite.com/cli! | bash
```

### 5. Install jq (JSON processor)
Needed for full-node and validator scripts.

```bash
# macOS
brew install jq
```

### 6. Install yq (YAML processor)
Needed for full-node and validator scripts.

```bash
# macOS
brew install yq
```

### 7. Install dasel (TOML modifier)

**macOS:**
```bash
brew install dasel
```

### 8. Build and Run

```bash
cd qadena_v3
./init.sh                    # Build the qadenad executable
./run.sh                     # Run the chain
./setup.sh                   # Set up sample wallets and credentials
./show_wallets.sh            # Display wallets
```

Check `HOWTO-DEMO.txt` for additional information.

## Adding New Full-Nodes to Existing Qadena network

### Prerequisites
Make sure your dev machine has a working qadenad and is running.

### Steps

#### 1. Prepare the New Machine
a.  Follow same instructions as above, then:
   ```bash
   ./init.sh
   ```

b. Test the setup:
   ```bash
   ./run.sh
   ```

#### 2. Add as Full Node
Use the `add_full_node.sh` script with the format:
```bash
./add_full_node.sh pioneer-name advertise-ip-address pioneer1-ip-address
```

**Example:**
```bash
./add_full_node.sh pioneer2 10.211.55.2 10.211.55.3
```

#### 3. Convert Full Node to Validator Node (Optional)
On the new machine, convert it to a validator node:
```bash
./convert_to_validator.sh
```
