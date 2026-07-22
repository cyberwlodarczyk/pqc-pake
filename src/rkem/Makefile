.PHONY: init
.DEFAULT_GOAL := init

%: %.c
	gcc $(CFLAGS) $(LDFLAGS) $^ -o $@ -lrkem -lkyber -lcrypto

init: ntt_init rkem_init

clean:
	rm ntt_init rkem_init
