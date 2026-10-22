<p align="center">
  <a href="https://GitHub.com/majd/ipatool/releases/"><img src="https://img.shields.io/github/release/majd/ipatool.svg?label=Release" alt="Release"></a>
  <a href="https://github.com/majd/ipatool/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
  <a href="https://github.com/sponsors/majd"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink.svg" alt="Sponsor"></a>
</p>

<p align="center">
  <code>ipatool</code> is a command line tool that allows you to search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps on the <a href="https://apps.apple.com">App Store</a>, and download <code>.ipa</code> or macOS <code>.pkg</code> app packages.
</p>

<p align="center">
  <img src="./resources/demo.gif" alt="Demo">
</p>

## Requirements

- A supported operating system (macOS, Linux, Windows or iOS).
- An Apple Account already configured to use the App Store.

## Installation

### Linux and Windows

You can grab the latest version of `ipatool` from [GitHub releases](https://github.com/majd/ipatool/releases).

### macOS

You can install `ipatool` using [Homebrew](https://brew.sh).

```shell
$ brew install ipatool
```

## Usage

To get started, run the following command.

```text
$ ipatool --help
A cli tool for interacting with Apple's ipa files

Usage:
  ipatool [command]

Available Commands:
  auth                 Authenticate with the App Store
  completion           Generate the autocompletion script for the specified shell
  download             Download iOS, iPadOS, tvOS, watchOS, visionOS, and macOS app packages from the App Store
  get-version-metadata Retrieves the metadata for a specific version of an app
  help                 Help about any command
  list-purchases       List apps owned by the authenticated App Store account
  list-versions        List the available versions of an App Store app
  mcp                  Serve App Store tools over MCP using stdio
  purchase             Obtain a license for the app from the App Store
  search               Search for iOS, iPadOS, tvOS, watchOS, visionOS, and macOS apps available on the App Store

Flags:
      --format format                sets output format for command; can be 'text', 'json' (default text)
  -h, --help                         help for ipatool
      --keychain-passphrase string   passphrase for unlocking keychain
      --non-interactive              run in non-interactive session
      --verbose                      enables verbose logs
  -v, --version                      version for ipatool

Use "ipatool [command] --help" for more information about a command.
```

**Note:** the tool runs in interactive mode by default. Use the `--non-interactive` flag
if running in an automated environment.

### FairPlay decryption

> **Experimental:** FairPlay decryption currently supports only macOS 27.0.1
> (build 26A428) with a freshly created Apple ID. It is not guaranteed to work.

`fairplay-decrypt` decrypts a personalized IPA using the embedded current-SINF
model recovered from macOS 27.0.1 build 26A428. This is the only FairPlay
profile currently supported. It needs no device state, Wine, or runtime
hardware call when the IPA matches that profile:

```shell
ipatool fairplay-decrypt --input App.ipa
```

`--model` is retained as an experimental development override. It is not a
promise of support for other macOS releases or FairPlay enrollments:

```shell
ipatool fairplay-decrypt \
  --input App.ipa \
  --model fairplay-enrollment.bin
```

The same experimental option is available as `--fairplay-model` when
decrypting directly after `ipatool download`. Model files contain private key
material and must be readable only by their owner; ipatool rejects group- or
world-readable files. ipatool does not generate these files and does not
support arbitrary profiles.

Pass `--fairplay-decrypt` to `ipatool download` to decrypt immediately after
download and SINF replication. The decoder validates the complete decrypted
`key `/`iviv`/`tmpr`/`righ`/`name` atom geometry and fails closed when the SINF
does not match the current model. Inputs are never overwritten; outputs and
private reports default beside the source IPA. A profile mismatch reports the
supported macOS release and fails closed. The decrypted analysis IPA must be
recursively re-signed before installation.

### FairPlay enrollment diagnostics

This diagnostic branch can preserve the transaction-bound FairPlay inputs from
one successful `ent/download` request:

```shell
ipatool download \
  --app-id 333903271 \
  --external-version-id 893310510 \
  --output X-12.36.ipa \
  --fairplay-capture-dir X-12.36-fairplay-capture
```

The capture directory must not already exist. It is created with private
permissions and contains `kbsync.bin`, `keybag.bin`, the returned SINF, and a
`receipt.json` containing selectors, byte lengths, and SHA-256 hashes. The
KBSync and keybag are taken from the same Store transaction. Passwords, 2FA
codes, cookies, and Store authentication tokens are not written.

The captured blobs are personalized material. Share the directory privately;
do not attach it to a public issue.

### MCP tools

Run `ipatool auth login` in a terminal, then configure your MCP client to launch the stdio server:

```json
{
  "mcpServers": {
    "ipatool": {
      "command": "ipatool",
      "args": ["mcp"]
    }
  }
}
```

## Compiling

The tool can be compiled using the Go toolchain.

```shell
$ go build -o ipatool
```

Unit tests can be executed with the following commands.

```shell
$ go generate ./...
$ go test -v ./...
```

## License

ipatool is released under the [MIT license](https://github.com/majd/ipatool/blob/main/LICENSE).
