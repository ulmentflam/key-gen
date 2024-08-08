# key-gen
A BIP-0044 compatible key generator for multiple blockchains. This is not a secure method, but is useful for quick key generation.

## 1Password Setup (Optional)

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



