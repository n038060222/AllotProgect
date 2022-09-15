CFLAGS_DEBUG := -g -DDEBUG -O0
CFLAGS := -Wall -pthread -fprofile-arcs -ftest-coverage -lpcap -ljson-c
# -std=c99 -D_POSIX_C_SOURCE=200809L
ifeq ($(DEBUG),1)
  CFLAGS := $(CFLAGS_DEBUG) $(CFLAGS)
endif
main : sniffer.c 
	clang $(CFLAGS) sniffer.c -mcmodel=large -O2 -fopenmp  -lpcap -o main -lrt
clean:
	rm *.gcov *.gcda *.gcno *.csv
	