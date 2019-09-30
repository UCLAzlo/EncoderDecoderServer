/*****************************************************************************
otp_enc.c
Author: Daniel Meirovitch
Date: May 31 2019

Description: Sends a plaintext and key string (with network sockets) to an 
OTP_ENC_D encryption service running on localhost <port>. Recieves ciphertext back
and prints to stdout.
*****************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define h_addr h_addr_list[0]

/*****************************************************************************
Global Variables + Function Prototypes
*****************************************************************************/
void error(const char *msg) { fprintf(stderr, msg); exit(2); } // Error function used for reporting issues
int createSocket(int port);
char* receiveMessage(int socketFD);
void sendMessage(int socketFD, char* message);
char* receiveData(int socketFD);
void sendData(int socketFD, char* message);

char* readFromFile(char* filename);
int validConnection(int socketFD);

int debug = 0;

/*****************************************************************************
Creates a connection to localhost on the specified port
Returns an error if there is an issue
*****************************************************************************/
int createSocket(int port)
{
	int socketFD;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char* hostname = "localhost";

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	serverHostInfo = gethostbyname(hostname);
	if (serverHostInfo == NULL) error("CLIENT: ERROR No such HOST\n");
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (socketFD < 0) error("CLIENT: ERROR opening socket\n");

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting\n");

	return socketFD;
}

/*****************************************************************************
Receives any message and saves it to the response parameter passed
Will loop until entire response has been received
Reports any error
*****************************************************************************/
char* receiveMessage(int socketFD)
{
	int charsRead;
	char buffer[1000];
	char* message;
	int messageSize;

	//read in the length of the incoming message
	charsRead = recv(socketFD, &messageSize, sizeof(int), 0);
	if (charsRead < 0) error("CLIENT: ERROR reading from socket\n");
	if(debug) fprintf(stderr, "CLIENT: I received this from the server: \"%d\"\n", messageSize);

	//allocate a buffer big enough for incoming message
	message = malloc((sizeof(char) * messageSize) + 1);
	memset(message, '\0', (sizeof(char) * messageSize) + 1);

	//loop until message received is as large as expected value
	while(strlen(message) < messageSize)
	{
		memset(buffer, '\0', sizeof(buffer));
		charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
		if (charsRead < 0) error("CLIENT: ERROR reading from socket\n");
		strcat(message, buffer);
	}
	if(debug) fprintf(stderr, "CLIENT: I received this from the server: \"%s\"\n", message);

	return message;
}

/*****************************************************************************
Sends the specified message
Reports any error
*****************************************************************************/
void sendMessage(int socketFD, char* message)
{
	int charsWritten;
	int messageSize = strlen(message);

	//send the length of the actual message first as INT
	charsWritten = send(socketFD, &messageSize, sizeof(int), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket\n");
	if (charsWritten < sizeof(int)) printf("CLIENT: WARNING: Not all data written to socket!\n");

	//then send actual message
	charsWritten = send(socketFD, message, strlen(message), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket\n");
	if (charsWritten < strlen(message)) printf("CLIENT: WARNING: Not all data written to socket!\n");
}

/*****************************************************************************
Receives a specified message and sends ack to confirm
*****************************************************************************/
char* receiveData(int socketFD)
{
	char* data = receiveMessage(socketFD);
	sendAck(socketFD);
	return data;
}

/*****************************************************************************
Sends a specified message to server and
Confirms receipt of entire message
*****************************************************************************/
void sendData(int socketFD, char* message)
{
	sendMessage(socketFD, message);
	recvAck(socketFD);
}

/*****************************************************************************
Sends OTP_ENC Client information to server
Receives response to check whether connection is setup to the correct server
*****************************************************************************/
int validConnection(int socketFD)
{
	int connectionIsValid = 0;
	char* status;
	char client[8] = "OTP_ENC\0";
	char* success = "ACCEPT";
	
	//Send Client Information to confirm OTP_ENC
	sendMessage(socketFD, client);
	status = receiveMessage(socketFD);

	//final check to see if connection is successfully established
	if(!strcmp(status, success))
		connectionIsValid = 1;
	free(status);

	return connectionIsValid;
}

/*****************************************************************************
Reads data in from file, performs checks for any bad characters
*****************************************************************************/
char* readFromFile(char* filename)
{
	//read data in from file
	char* content = NULL;
	size_t len = 0;
	FILE* input = fopen(filename, "r");
	getline(&content, &len, input);

	//strip newline from end of input
    content[strcspn(content, "\n")] = '\0';

	//verify contents
	for(int i = 0; i < strlen(content); i++)
	{
		if((content[i] < 'A' || content[i] > 'Z') && content[i] != ' ')
		{
			fprintf(stderr, "Bad character encountered in file %s\n", filename);
			exit(2);
		}
	}

	fclose(input);
	return content;
}


/*****************************************************************************
Main Driver for program
*****************************************************************************/
int main(int argc, char *argv[])
{
	int socketFD;
	int portNumber;
    
    // Check usage & args
	if (argc < 4) { fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); exit(0); }

	//setup strings from files
	char* plaintext = readFromFile(argv[1]);
	char* key = readFromFile(argv[2]);
	if(strlen(plaintext) > strlen(key))
		error("Key is too short for selected plaintext");

	//setup socket
	portNumber = atoi(argv[3]);
	socketFD = createSocket(portNumber);
	//verify connection to otp_enc_d, exit and return ERROR if failed
	if(!validConnection(socketFD))
	{
		fprintf(stderr, "CLIENT: ERROR: Can't connect to OTP_ENC_D on localhost port %d\n.", portNumber);
		exit(2);
	}

	//send decrypted data and receive encrypted data
	sendData(socketFD, plaintext);
	sendData(socketFD, key);
	char* encrypted = receiveData(socketFD);
	printf("%s\n", encrypted);

	//free resources and exit
	free(plaintext);
	free(key);
	free(encrypted);
	close(socketFD);
	return 0;
}
