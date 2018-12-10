#!/usr/bin/env pwsh
Remove-Variable * -ErrorAction SilentlyContinue

# This is a recode of https://github.com/coinbase/assume-role

# START USAGE DOCUMENTATION
# assume-role is a command line tool to help assume roles through a bastion account with MFA.
# Store your bastion account credentials here ~/.aws/credentials
#
# Usage: assume-role [account_name] [role] [mfa_token] [aws-region]
#
# account_name          account id or alias
#                       aliases stored in ~/.aws/accounts as JSON {"alias": account_id}
#                       [default 'default']
# role                  the role to assume into the account
#                       [default 'read']
# mfa_token             The MFA token for the user
#                       only valid if not using SAML for auth
#
# aws_region            region to assume into default set in ~/.aws/config
#
# END USAGE DOCUMENTATION

function echo_out() {
    # If this is outputting to an eval statement we need to output a "echo" as well
    if ($OUTPUT_TO_EVAL -eq $null) {
        return $PsBoundParameters.Values + $args
    }
    else {
        return write-host $PSsBoundParameters.Values $args
    }
}

function assume-role() {
    setup $args
    if ($LastExitCode -ne 0) {
        return 1
    }

    if ($AWS_ASSUME_ROLE_AUTH_SCHEME -eq "saml") {
        # assume-role-with-saml
        echo "SAML is not implemented yet"
        return 1
    }
    elseif ($AWS_ASSUME_ROLE_AUTH_SCHEME -eq "bastion") {
        if (assume-role-with-bastion -eq 1) {
            return 1
        }
    }
    else {
        return 1
    }

    export-envars
    debug-info
    cleanup
}

function setup() {
    #######
    # PRE-CONDITIONS
    #######

    # requires aws
    try {
        aws --version > $null
    }
    catch {
        echo_out "assume-role requires 'aws' to be installed"
        return 1
    }

    # INPUTS
    if ($AWS_ASSUME_ROLE_AUTH_SCHEME -eq "saml") {
        $account_name_input = $args[0][0][0]
        $role_input = $args[0][0][1]
        $aws_region_input = $args[0][0][2]
    }
    else {
        $account_name_input = $args[0][0][0]
        $role_input = $args[0][0][1]
        $script:mfa_token_input = $args[0][0][2]
        $aws_region_input = $args[0][0][3]
    }

    # DEFAULT VARIABLES
    if (!(Get-Variable 'ACCOUNTS_FILE' -Scope Global -ErrorAction 'Ignore')) {
        $ACCOUNTS_FILE = (Resolve-path ~).Path + "/.aws/accounts"
    }
    if (!(Get-Variable 'SAML_FILE' -Scope Global -ErrorAction 'Ignore')) {
        $SAML_FILE = (Resolve-path ~).Path + "/.saml/credentials"
    }
    $script:SESSION_TIMEOUT = 43200
    $script:ROLE_SESSION_TIMEOUT = 3600
    if (!(Get-Variable 'AWS_ASSUME_ROLE_AUTH_SCHEME' -Scope Global -ErrorAction 'Ignore')) {
        $script:AWS_ASSUME_ROLE_AUTH_SCHEME = "bastion"
    }

    if ($AWS_ASSUME_ROLE_AUTH_SCHEME -eq "saml" -and $SAML_IDP_ASSERTION_URL -notmatch "^https") {
        echo_out "[WARNING] - Using non-https url ($SAML_IDP_ASSERTION_URL) for SAML authentication. Your credentials may be sent via plaintext."
    }

    # Force use of ~/.aws/credentials file which contains aws login account
    remove-item env:\AWS_ACCESS_KEY_ID -ErrorAction SilentlyContinue
    remove-item env:\AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue
    remove-item env:\AWS_SESSION_TOKEN -ErrorAction SilentlyContinue
    remove-item env:\AWS_SECURITY_TOKEN -ErrorAction SilentlyContinue

    #######
    # SETUP
    #######

    # load default assume-role profile if available, use "default" otherwise
    if (Get-Variable 'AWS_PROFILE_ASSUME_ROLE' -Scope Global -ErrorAction 'Ignore') {
        echo_out "Using assume-role default profile: $AWS_PROFILE_ASSUME_ROLE"
        $script:default_profile = $AWS_PROFILE_ASSUME_ROLE
    }
    else {
        $script:default_profile = "default"
    }

    # load user-set ROLE_SESSION_TIMEOUT (up to 12h, 43200 seconds), use default 1h defined above otherwise
    if (Get-Variable 'AWS_ROLE_SESSION_TIMEOUT' -Scope Global -ErrorAction 'Ignore') {
        $script:ROLE_SESSION_TIMEOUT = $AWS_ROLE_SESSION_TIMEOUT
    }

    # set account_name
    if (($account_name_input -eq $null) -and ($OUTPUT_TO_EVAL -eq $null)) {
        $account_name = Read-Host "Assume Into Account [default]"
        # default
        if ($account_name -eq $null) {
            $account_name = "default"
        }
    }
    else {
        $account_name = $account_name_input
    }

    # set account_id
    if (Test-Path $ACCOUNTS_FILE) {
        $script:account_id = (get-content $ACCOUNTS_FILE -Raw | ConvertFrom-Json).$account_name
    }

    # If cant find the alias then set the input as the account id
    if ($account_id -eq $null) {
        $script:account_id = $account_name
    }

    # Validate Account ID
    if ($account_id -notmatch "^[0-9]{12}$") {
        echo_out "account_id `"$account_id`" is incorrectly formatted AWS account id"
        return 1
    }

    # set role
    if (($role_input -eq $null) -and ($OUTPUT_TO_EVAL -eq $null)) {
        $script:role = Read-Host "Assume Into Role [read]"
        if ($role -eq $null) {
            $script:role = "read"
        }
    }
    else {
        $script:role = $role_input
    }

    if ($role -eq $null) {
        echo_out "role not defined"
        return 1
    }

    # set region
    $script:AWS_CONFIG_REGION = "$(aws configure get region --profile $default_profile)"
    if (($aws_region_input -eq $null) -and ($AWS_REGION -eq $null) -and ($AWS_DEFAULT_REGION -eq $null) -and ($AWS_CONFIG_REGION -eq $null) -and ($OUTPUT_TO_EVAL -eq $null)) {
        $region = Read-Host "Assume Into Region [us-east-1]"
        if ($role -eq $null) {
            $region = "us-east-1"
        }
    }
    elseif ($aws_region_input -ne $null) {
        # if there is a $aws_region_input then set to $aws_region_input
        $region = $aws_region_input
    }
    elseif ($AWS_REGION -ne $null) {
        # if there is a $AWS_REGION then set to $AWS_REGION
        $region = $AWS_REGION
    }
    elseif ($AWS_DEFAULT_REGION -ne $null) {
        # if there is a $AWS_DEFAULT_REGION then set to $AWS_DEFAULT_REGION
        $region = $AWS_DEFAULT_REGION
    }
    elseif ($AWS_CONFIG_REGION -ne $null) {
        $region = $AWS_CONFIG_REGION
    }

    if ($region -eq $null) {
        echo_out "role not defined"
        return 1
    }

    $env:AWS_REGION = $region
    $env:AWS_DEFAULT_REGION = $region
}

# TODO: assume-role-with-saml()

function assume-role-with-bastion() {
    # Activate our session
    $NOW = (get-date -UFormat "%s").Split("(,|.)")[0]
    if ($AWS_SESSION_START -eq $null) {
        $AWS_SESSION_START = 0
    }

    $ABOUT_SESSION_TIMEOUT = $SESSION_TIMEOUT - 200
    $SESSION_TIMEOUT_DELTA = $NOW - $AWS_SESSION_START
    
    # if session doesn't exist, or is expired
    if ($ABOUT_SESSION_TIMEOUT -lt $SESSION_TIMEOUT_DELTA) {
        # We'll need a token to renew session
        if (($mfa_token_input -eq $null) -and ($OUTPUT_TO_EVAL -eq $null)) {
            $mfa_token = Read-Host "MFA Token"
        }
        else {
            $mfa_token = $mfa_token_input
        }

        if ($mfa_token -eq $null) {
            echo_out "mfa_token is not defined"
            return 1
        }
        # get the username attached to your default creds
        $script:AWS_USERNAME = $(aws iam get-user --query User.UserName --output text --profile $default_profile)

        # get MFA device attached to default creds
        $script:MFA_DEVICE_ARGS = "--user-name $AWS_USERNAME --query MFADevices[0].SerialNumber --output text --profile $default_profile"
        $script:MFA_DEVICE = $(aws iam list-mfa-devices --user-name $AWS_USERNAME --query MFADevices[0].SerialNumber --output text --profile $default_profile)
        $MFA_DEVICE_STATUS = $?

        if ($MFA_DEVICE_STATUS -ne $true) {
            echo_out "aws iam list-mfa-devices error"
            return 1
        }

        # 12 hour MFA w/ Session Token, which can then be reused
        $script:SESSION_ARGS = "--duration-seconds $SESSION_TIMEOUT --serial-number $MFA_DEVICE --token-code $mfa_token --profile $default_profile"
        $script:SESSION = $(aws sts get-session-token --duration-seconds $SESSION_TIMEOUT --serial-number $MFA_DEVICE --token-code $mfa_token --profile $default_profile)
        $SESSION_STATUS = $?

        if ($SESSION_STATUS -ne $true) {
            echo_out "aws sts get-session-token error"
            return 1
        }

        # Save Primary Credentials
        $AWS_SESSION_START = $NOW
        $AWS_SESSION_ACCESS_KEY_ID = ($SESSION | ConvertFrom-Json).Credentials.AccessKeyId
        $AWS_SESSION_SECRET_ACCESS_KEY = ($SESSION | ConvertFrom-Json).Credentials.SecretAccessKey
        $AWS_SESSION_SESSION_TOKEN = ($SESSION | ConvertFrom-Json).Credentials.SessionToken
        $AWS_SESSION_SECURITY_TOKEN = $AWS_SESSION_SESSION_TOKEN
    }

    # Use the Session in the login account
    $env:AWS_ACCESS_KEY_ID = $AWS_SESSION_ACCESS_KEY_ID
    $env:AWS_SECRET_ACCESS_KEY = $AWS_SESSION_SECRET_ACCESS_KEY
    $env:AWS_SESSION_TOKEN = $AWS_SESSION_SESSION_TOKEN
    $env:AWS_SECURITY_TOKEN = $AWS_SESSION_SECURITY_TOKEN

    $ROLE_SESSION_START = $NOW

    # Now drop into a role using session token's long-lived MFA
    $script:ROLE_SESSION_ARGS = "--role-arn arn:aws:iam::${account_id}:role/$role --external-id $account_id --duration-seconds $ROLE_SESSION_TIMEOUT --role-session-name $((get-date -UFormat '%s').Split('(,|.)')[0])"
    $script:ROLE_SESSION = $(aws sts assume-role --role-arn arn:aws:iam::${account_id}:role/$role --external-id $account_id --duration-seconds $ROLE_SESSION_TIMEOUT --role-session-name $((get-date -UFormat "%s").Split("(,|.)")[0]))
    if ($LastExitCode -ne 0) {
        $script:ROLE_SESSION = "fail"
    }
}

function export-envars() {
    if ($ROLE_SESSION -eq "fail") {
        echo_out "Failed to export session envars."
        # This will force a new session next time assume-role is run
        remove-item env:\AWS_SESSION_START -ErrorAction SilentlyContinue
    }
    else {
        $env:AWS_ACCESS_KEY_ID = ($ROLE_SESSION | ConvertFrom-Json).Credentials.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = ($ROLE_SESSION | ConvertFrom-Json).Credentials.SecretAccessKey
        $env:AWS_SESSION_TOKEN = ($ROLE_SESSION | ConvertFrom-Json).Credentials.SessionToken
        $env:AWS_SECURITY_TOKEN = $AWS_SESSION_TOKEN
        $env:AWS_ACCOUNT_ID = $account_id
        $env:AWS_ACCOUNT_NAME = $account_name
        $env:AWS_ACCOUNT_ROLE = $role
        $env:ROLE_SESSION_START = $ROLE_SESSION_START
        $env:GEO_ENV = $account_name # For GeoEngineer https://github.com/coinbase/geoengineer
        echo_out "Success! IAM session envars are exported."
    }
    
    # OUTPUTS ALL THE EXPORTS for eval $(assume-role [args])
    if ($OUTPUT_TO_EVAL -ne $null) {
        echo "$env:AWS_REGION=`"$AWS_REGION`";"
        echo "$env:AWS_DEFAULT_REGION=`"$AWS_DEFAULT_REGION`";"
        echo "$env:AWS_ACCESS_KEY_ID=`"$AWS_ACCESS_KEY_ID`";"
        echo "$env:AWS_SECRET_ACCESS_KEY=`"$AWS_SECRET_ACCESS_KEY`";"
        echo "$env:AWS_SESSION_TOKEN=`"$AWS_SESSION_TOKEN`";"
        echo "$env:AWS_ACCOUNT_ID=`"$AWS_ACCOUNT_ID`";"
        echo "$env:AWS_ACCOUNT_NAME=`"$AWS_ACCOUNT_NAME`";"
        echo "$env:AWS_ACCOUNT_ROLE=`"$AWS_ACCOUNT_ROLE`";"
        echo "$env:AWS_SESSION_ACCESS_KEY_ID=`"$AWS_SESSION_ACCESS_KEY_ID`";"
        echo "$env:AWS_SESSION_SECRET_ACCESS_KEY=`"$AWS_SESSION_SECRET_ACCESS_KEY`";"
        echo "$env:AWS_SESSION_SESSION_TOKEN=`"$AWS_SESSION_SESSION_TOKEN`";"
        echo "$env:AWS_SESSION_SECURITY_TOKEN=`"$AWS_SESSION_SESSION_TOKEN`";"
        echo "$env:AWS_SESSION_START=`"$AWS_SESSION_START`";"
        echo "$env:GEO_ENV=`"$GEO_ENV`";"
        echo "$env:AWS_PROFILE_ASSUME_ROLE=`"$AWS_PROFILE_ASSUME_ROLE`";"
        echo "$env:AWS_SECURITY_TOKEN=`"$AWS_SESSION_TOKEN`";"
    }

}

function debug-info() {
    # USED FOR TESTING AND DEBUGGING
    if ($DEBUG_ASSUME_ROLE -eq $true) {
        echo "AWS_CONFIG_REGION=`"$AWS_CONFIG_REGION`";"
        echo "AWS_USERNAME=`"$AWS_USERNAME`";"
        echo "MFA_DEVICE_ARGS=`"$MFA_DEVICE_ARGS`";"
        echo "MFA_DEVICE=`"$MFA_DEVICE`";"
        echo "SESSION_ARGS=`"$SESSION_ARGS`";"
        echo "SESSION=`"$SESSION`";"
        echo "ROLE_SESSION_ARGS=`"$ROLE_SESSION_ARGS`";"
        echo "ROLE_SESSION=`"$ROLE_SESSION`";"
        echo "SESSION_TIMEOUT=`"$SESSION_TIMEOUT`";"
        echo "ROLE_SESSION_TIMEOUT=`"$ROLE_SESSION_TIMEOUT`";"
        echo "AWS_PROFILE_ASSUME_ROLE=`"$AWS_PROFILE_ASSUME_ROLE`";"
    }
}

function cleanup() {
    remove-item env:\ROLE_SESSION -ErrorAction SilentlyContinue
    remove-item env:\ROLE_SESSION_ARGS -ErrorAction SilentlyContinue
    remove-item env:\SESSION -ErrorAction SilentlyContinue
    remove-item env:\SESSION_ARGS -ErrorAction SilentlyContinue
    remove-item env:\SESSION_TIMEOUT -ErrorAction SilentlyContinue
    remove-item env:\api_body -ErrorAction SilentlyContinue
    remove-item env:\saml_password -ErrorAction SilentlyContinue
    remove-item env:\account_name_input -ErrorAction SilentlyContinue
    remove-item env:\role_input -ErrorAction SilentlyContinue
    remove-item env:\aws_region_input -ErrorAction SilentlyContinue
    remove-item env:\mfa_token -ErrorAction SilentlyContinue
}

# Not sure if this eval-thing is necessary in Powershell so I implemented it roughly but didn't enable it
#$script:OUTPUT_TO_EVAL = "true"
assume-role $args
