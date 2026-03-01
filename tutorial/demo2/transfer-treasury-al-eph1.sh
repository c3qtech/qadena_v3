. ../funcs.sh

run_cmd "qadenad keys show al-eph1"
account=`qadenad keys show al-eph1 -a`
minimum_gas_prices="500000000aqdn"
run_cmd "qadenad tx bank send treasury $account 333000000qdn --from treasury --gas auto --gas-prices $minimum_gas_prices --gas-adjustment 1.5 --yes"

