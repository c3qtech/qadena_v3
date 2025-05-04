#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

set -e

prefix=""
bf=""
amount=""

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            prefix="$2"
            shift 2
            ;;
        --bf)
            bf="$2"
            shift 2
            ;;
        --amount)
            amount="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--prefix <prefix>] [--bf <bf>] [--amount <amount>]"
            echo "--prefix <prefix>: Add a prefix to the test users"
            echo "--bf <bf>: Add a bf to the test users"
            echo "--amount <amount>: Add an amount to the test users"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "try: setup_credential.sh --help"
            exit 1
            ;;
    esac
done

if [ -z "$prefix" ] || [ -z "$bf" ] || [ -z "$amount" ]; then
    echo "Missing required options: prefix, bf, amount"
    exit 1
fi

firstname="$prefix-juan"
lastname="$prefix-valdez"
middlename="$prefix-doe"
birthdate="1970-Feb-02"
nationality="ph"
residence="us"
gender="M"
phone="1234567890"
email="juanvaldez@c3qtech.com"

echo "-------------------------"
echo "Creating personal-info"
echo "-------------------------"
qadenad_alias tx qadena create-credential $amount $bf personal-info $firstname $middlename $lastname $birthdate $nationality $residence $gender --from secidentitysrvprv --yes || exit 1

echo "-------------------------"
echo "Creating phone"
echo "-------------------------"
qadenad_alias tx qadena create-credential $amount $bf phone-contact-info $phone --from secidentitysrvprv --yes || exit 1

echo "-------------------------"
echo "Creating email"
echo "-------------------------"
qadenad_alias tx qadena create-credential $amount $bf email-contact-info $email --from secidentitysrvprv --yes || exit 1


