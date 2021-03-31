all:
	gcc clone3_owner_ns.c util.c -o clone3_owner_ns
	gcc clone3_set_tid_vs_owner_ns.c util.c -o clone3_set_tid_vs_owner_ns
