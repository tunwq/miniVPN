INCLUDE_FLODER = "./include"
SRC_FLODER = "./src"
BIN_FLODER = "./bin"
all: 
	gcc -I $(INCLUDE_FLODER) -o $(BIN_FLODER)/tlsclient $(SRC_FLODER)/tlsclient.c -lssl -lcrypto 
	gcc -I $(INCLUDE_FLODER) -o $(BIN_FLODER)/tlsserver $(SRC_FLODER)/tlsserver.c -lssl -lcrypto 
	gcc -I $(INCLUDE_FLODER) -o $(BIN_FLODER)/vpnserver_tls $(SRC_FLODER)/vpnserver_tls.c -lssl -lcrypto -lcrypt
	gcc -I $(INCLUDE_FLODER) -o $(BIN_FLODER)/vpnserver_tls_multiclient $(SRC_FLODER)/vpnserver_tls_multiclient.c -lssl -lcrypto -lcrypt
	gcc -I $(INCLUDE_FLODER) -o $(BIN_FLODER)/vpnclient_tls $(SRC_FLODER)/vpnclient_tls.c -lssl -lcrypto
clean: 
	rm $(BIN_FLODER)/*

