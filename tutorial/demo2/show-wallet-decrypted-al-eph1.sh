. ../funcs.sh

run_cmd "qadenad keys show al-eph1 -a"
run_cmd "qadenad query qadena show-wallet $(qadenad keys show al-eph1 -a) --decrypt-as $(qadenad keys show al-eph1 -a)"


