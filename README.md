# key-gen
A BIP-0044 compatible key generator for multiple blockchains. This is not a secure method, but is useful for quick key generation.

## Installation


## Usage
### key-gen
```
key-gen is a CLI tool to generate keys for various blockchains. It supports Bitcoin, Ethereum, and other blockchains.It supports saving keys to 1Password, and the file system in encrypted or unencrypted json. The keys are generated from a BIP32 seed and support BIP44, BIP49, and BIP84 derivation paths. This project has not and will not be audited by a security professional. Use at your own risk.

Usage:
  key-gen [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  create      Create unencrypted accounts with private keys to 1Password and/or the file system
  decrypt     Decrypt keys
  encrypt     Generate encrypted accounts with private keys to the file system
  help        Help about any command

Flags:
  -f, --file string       The path to save the keys or read the keys from (optional, required for decrypt)
  -h, --help              help for key-gen
  -p, --password string   Password for encryption (optional, required for encrypt/decrypt)
  -s, --suppress          Suppress the mnemonic and private keys from the output
  -t, --toggle            Help message for toggle

Use "key-gen [command] --help" for more information about a command.
```

### key-gen create
```bash
key-gen create
```
```
Create unencrypted accounts and keys for various blockchains. 
It supports Bitcoin, Ethereum, and other blockchains that support BIP-0032 and BIP-0044 keys. 
It accepts or generates the base mnemonic and can encrypt the mnemonic with a password.

Usage:
  key-gen create [flags]

Flags:
  -a, --accounts int                      Number of accounts to generate (default 1)
  -c, --compressed                        Compress the output keys (default true)
  -e, --encrypt-mnemonic                  Encrypt the mnemonic with a password
  -h, --help                              help for create
  -m, --mnemonic string                   Base mnemonic for the wallet (optional)
  -n, --name string                       Name of the wallet (default "Generated Wallet")
  -t, --op-service-account-token string   1Password service account token (optional)
  -v, --op-vault-id string                1Password vault ID (optional)
      --save                              Save the wallet to a file or to 1Password (default true)

Global Flags:
  -f, --file string       The path to save the keys or read the keys from (optional, required for decrypt)
  -p, --password string   Password for encryption (optional, required for encrypt/decrypt)
  -s, --suppress          Suppress the mnemonic and private keys from the output
``` 
### key-gen encrypt
```bash
key-gen encrypt --password <password>
```
```
Generates AES-256 encrypted accounts and keys to the file system at ~/.key-gen or a specified directory. 
It supports Bitcoin, Ethereum, and other blockchains that support BIP-0032 and BIP-0044 keys. 
It accepts or generates the base mnemonic and can encrypt the mnemonic with a password.

Usage:
  key-gen encrypt [flags]

Flags:
  -a, --accounts int       Number of accounts to generate (default 1)
  -c, --compressed         Compress the output keys (default true)
  -e, --encrypt-mnemonic   Encrypt the mnemonic with a password
  -h, --help               help for encrypt
  -m, --mnemonic string    Base mnemonic for the wallet (optional)
  -n, --name string        Name of the wallet (default "Generated Wallet")

Global Flags:
  -f, --file string       The path to save the keys or read the keys from
  -p, --password string   Password for encryption (optional, required for encrypt/decrypt)
  -s, --suppress          Suppress the mnemonic and private keys from the output

``` 

### key-gen decrypt
```bash
key-gen decrypt --password <password> --file <file>
```
```
Decrypt keys that were encrypted when generated. 
The default path is .key-gen in the user's home directory.

Usage:
  key-gen decrypt [flags]

Flags:
  -h, --help   help for decrypt

Global Flags:
  -f, --file string       The path to save the keys or read the keys from (optional, required for decrypt)
  -p, --password string   Password for encryption (optional, required for encrypt/decrypt)
  -s, --suppress          Suppress the mnemonic and private keys from the output

``` 

## 1Password Setup (Optional)

### Warning
This is an optional step. If you do not want to use 1Password, you can skip this step. The 1Password SDK is still in deep beta and could change at any time! Use at your own risk.

### Step 1: Create a service account
Create a [1Password Service Account](https://developer.1password.com/docs/service-accounts/get-started/) and give it access to the vaults where the secrets you want to use with the SDK are saved.

To allow the SDK to update items, make sure to give the service account both read and write permissions in the appropriate vaults.

### Step 2: Provision your service account token
The 1Password SDK uses your service account token to authenticate to 1Password. We recommend provisioning your token from the environment.

Use the following example to provision your token to an environment variable named `OP_SERVICE_ACCOUNT_TOKEN`. You can also provision your token in other ways, like using a .env file, or passing it directly to the `--op-service-account-token` flag.

```bash
export OP_SERVICE_ACCOUNT_TOKEN=<your-service-token>
```

### Step 3: Provision your vaultID
The best method to get your 1Password vaultID is to use the 1Password CLI. You can install the CLI by following the instructions [here](https://support.1password.com/command-line-getting-started/).

Get your vaultID by running the `op vault list` command. Then export the vaultID to an environment variable named `OP_VAULT_ID` or pass it directly using the `--op-vault-id` flag.

```bash
export OP_VAULT_ID=<your-vault-id>
```



