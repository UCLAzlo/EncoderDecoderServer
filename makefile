
# Format based on www.cs.bu.edu/teaching/cpp/writing-makefiles/
# *****************************************************
# G++ Variables

CC = gcc
CFLAGS += -Wall -g -std=c99

# ****************************************************
# Objects required for compilation/executable

all: enc_key_generator encrypt_client encrypt_daemon decrypt_client decrypt_daemon

enc_key_generator: enc_key_generator.o
	$(CC) -o enc_key_generator enc_key_generator.o $(CFLAGS)

enc_key_generator.o:

encrypt_client: encrypt_client.o
	$(CC) -o encrypt_client encrypt_client.o $(CFLAGS)

encrypt_client.o:

encrypt_daemon: encrypt_daemon.o
	$(CC) -o encrypt_daemon encrypt_daemon.o $(CFLAGS)

encrypt_daemon.o:

decrypt_client: decrypt_client.o
	$(CC) -o decrypt_client decrypt_client.o $(CFLAGS)

decrypt_client.o:

decrypt_daemon: decrypt_daemon.o
	$(CC) -o decrypt_daemon decrypt_daemon.o $(CFLAGS)

decrypt_daemon.o:

clean:
		-rm -rf *.o enc_key_generator encrypt_client encrypt_daemon decrypt_client decrypt_daemon *.txt