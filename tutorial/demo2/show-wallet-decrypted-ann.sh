. ../funcs.sh

run_cmd "qadenad keys show ann -a"
run_cmd "qadenad query qadena show-wallet $(qadenad keys show ann -a) --decrypt-as $(qadenad keys show ann -a)"


