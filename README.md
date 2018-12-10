# powershell-assume-role
[coinbase/assume-role](https://github.com/coinbase/assume-role) rewritten in Powershell

Table of contents:

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)

## Overview

Assume IAM roles through an **AWS Bastion** account with **MFA** via the command line.

**AWS Bastion** accounts store only IAM users providing a central, isolated account to manage their credentials and access. Trusting AWS accounts create IAM roles that the Bastion users can assume, to allow a single user access to multiple accounts resources. Under this setup, `assume-role` makes it easier to follow the standard security practices of MFA and short lived credentials.

### What doesn't work
This is a almost 1:1 copy of [coinbase/assume-role](https://github.com/coinbase/assume-role) rewritten in Powershell.
The SAML part of the original [coinbase/assume-role](https://github.com/coinbase/assume-role) isn't implemented at this time.

## Installation
### Prerequisites

Before using assume-role make sure the following prerequisites have been met.

1. Windows PowerShell 5.x or PowerShell Core 6.0.
   You can get PowerShell Core 6.0 for Windows, Linux or macOS from [here](https://github.com/PowerShell/PowerShell).
   Check your PowerShell version by executing `$PSVersionTable.PSVersion`.

2. On Windows, script execution policy must be set to either `RemoteSigned` or `Unrestricted`.
   Check the script execution policy setting by executing `Get-ExecutionPolicy`.
   If the policy is not set to one of the two required values, run PowerShell as Administrator and
   execute `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm`.

3. Install the AWS Command Line Interface
   [on Microsoft Windows](https://docs.aws.amazon.com/cli/latest/userguide/install-windows.html)
   [on macOS](https://docs.aws.amazon.com/cli/latest/userguide/install-macos.html#awscli-install-osx-path)
   [on Linux](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html)

4. Add the AWS CLI Executable to your Command Line Path if `aws` isn't responding after installation
   [Windows](https://docs.aws.amazon.com/cli/latest/userguide/install-windows.html#awscli-install-windows-path)
   [macOS](https://docs.aws.amazon.com/cli/latest/userguide/install-macos.html#awscli-install-osx-path)
   [Linux](https://docs.aws.amazon.com/cli/latest/userguide/install-linux.html#install-linux-path)

5. Create default profile with `aws configure`

### Execution

There are two variants.

#### 1. Simple execution

1. clone this repository

2. `cd` into the cloned directory

3. run `./assume-role.ps1`

#### 2. Make it executable

1. Clone this repository.

2. Create your personal execution folder. For example: `C:\Users\<User>\bin`.
   (Or use your existing one)

3. Copy or move assume-role.ps1 from step 1 to path from step 2.

3. Press the Windows key and type environment variables.

4. Choose Edit environment variables for your account.

5. Choose PATH and then choose Edit.

6. Add path from step 2 to the Variable value field

7. Choose OK twice to apply the new settings.

8. Close any running command prompts and re-open.

9. Open Powershell and run `assume-role`.
   Or open `cmd.exe` and run `powershell assume-role`

### Usage
Assume-role can be executed with or without parameters.
Every Parameter is optional but you have to keep the order.
So if you want to set the `role` parameter you also have to set `account_name`.

Values neither set by you nor determined by assume-role will ask you for input.

#### Usage in general
```
Usage: assume-role [account_name] [role] [mfa_token] [aws-region]
account_name          account id or alias
                      aliases stored in ~/.aws/accounts as JSON {"alias": account_id}
                      [default 'default']
role                  the role to assume into the account
                      [default 'read']
mfa_token             The MFA token for the user
                      only valid if not using SAML for auth
aws_region            region to assume into default set in ~/.aws/config
```

#### Additional information
The script assumes you'd like to use your default aws profile defined with `aws configure`.
If you want to use another profile, run the script like this `$AWS_PROFILE_ASSUME_ROLE="profilename"; assume-role`
