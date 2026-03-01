. ../funcs.sh

run_cmd "qadenad keys show test-account"
account=`qadenad keys show test-account -a`
minimum_gas_prices="500000000aqdn"
run_cmd "qadenad tx bank send treasury $account 555qdn --from treasury --gas auto --gas-prices $minimum_gas_prices --gas-adjustment 1.5 --yes"








