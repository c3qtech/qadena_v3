. ../funcs.sh

run_cmd "qadenad keys show ann-eph1 -a"
run_cmd "qadenad query qadena show-wallet $(qadenad keys show ann-eph1 -a) --decrypt-as $(qadenad keys show ann-eph1 -a)"


