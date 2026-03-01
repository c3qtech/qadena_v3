. ../funcs.sh

run_cmd "qadenad keys show al -a"
run_cmd "qadenad query qadena show-wallet $(qadenad keys show al -a) --decrypt-as $(qadenad keys show al -a)"


