/*****************************************************************************
otp_enc_d.c
Author: Daniel Meirovitch
Date: May 31 2019

Description: Runs as a server daemon. Listens on provided port for the
OTP_ENC client. It will receive a plaintext and key file from OTP_ENC and
convert the plaintext to ciphertext. It will then return that data back to
the OTP_ENC client.

Can accept up to 5 connections
*****************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <fcntl.h>

/*****************************************************************************
Global Variables + Function Prototypes
*****************************************************************************/
#define MAXCIPHER 27
#define MAXCON 5

void error(const char *msg)
{
	perror(msg);
	exit(1);
} // Error function used for reporting issues
void initBackgroundPIDs();
void reapZombies();
int createListenSocket(int port);
void sendAck(int socketFD);
void recvAck(int socketFD);
char *receiveMessage(int socketFD);
void sendMessage(int socketFD, char *message);
char *receiveData(int socketFD);
void sendData(int socketFD, char *message);

int verifyClient(int socketFD);
char *encryptData(char *message, char *key);
void processClient(int listenSocketFD);

int debug = 0;

struct pidArray
{
	pid_t data[MAXCON];
	int count;
};

struct pidArray backgroundPIDs;

/*****************************************************************************
Sets the global background PID array to all 0s and count to 0
*****************************************************************************/
void initBackgroundPIDs()
{
	int i;
	for (i = 0; i < MAXCON; i++)
		backgroundPIDs.data[i] = 0;
	backgroundPIDs.count = 0;
}

/*****************************************************************************
Loops through all running background processes, reap any zombies
*****************************************************************************/
void reapZombies()
{
	int i;
	for (i = 0; i < backgroundPIDs.count; i++)
	{
		int childExitMethod = -5;
		//if process completed, print data and remove data from array
		if (waitpid(backgroundPIDs.data[i], &childExitMethod, WNOHANG))
		{
			backgroundPIDs.data[i] = backgroundPIDs.data[backgroundPIDs.count - 1];
			backgroundPIDs.count--;
			i--;
		}
	}
}

/*****************************************************************************
Creates a listening socket on the Specified Port
Used by parent process to listen for incoming connections
*****************************************************************************/
int createListenSocket(int port)
{
	int listenSocketFD;
	struct sockaddr_in serverAddress;

	//setup socket struct for server
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(port);
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	// Set up the socket and report error if needed
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSocketFD < 0)
		error("ERROR opening socket");

	// Enable the socket to begin listening for up to 5 connections
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
		error("ERROR on binding");
	listen(listenSocketFD, MAXCON);

	return listenSocketFD;
}

/*****************************************************************************
Receives response from socket, confirms response is an ACK
*****************************************************************************/
void recvAck(int socketFD)
{
	int charsRead;
	char *ack = "ACK";
	char response[10];

	memset(response, '\0', sizeof(response));
	charsRead = recv(socketFD, response, sizeof(response) - 1, 0);

	if (charsRead < 0)
		error("SERVER: ERROR reading from socket\n");
	if (debug)
		fprintf(stderr, "SERVER: I received this from the client: \"%s\"\n", response);
	if (strcmp(response, ack))
		error("SERVER: ERROR Did not receive ACK when expected\n");
}

/*****************************************************************************
Sends an ACK on the connected socket, indicates successful receipt of packet
*****************************************************************************/
void sendAck(int socketFD)
{
	int charsWritten;
	char *ack = "ACK";
	charsWritten = send(socketFD, ack, sizeof(ack), 0);
	if (charsWritten < sizeof(ack))
		error("ERROR writing to socket");
}

/*****************************************************************************
Receives any message and saves it to the response parameter passed
Will loop until entire response has been received
Reports any error
*****************************************************************************/
char *receiveMessage(int socketFD)
{
	int charsRead;
	char buffer[1000];
	char *message;
	int messageSize;

	//read in the length of the incoming message
	charsRead = recv(socketFD, &messageSize, sizeof(int), 0);
	if (charsRead < 0)
		error("SERVER: ERROR reading from socket\n");
	if (debug)
		fprintf(stderr, "SERVER: I received this from the client: \"%d\"\n", messageSize);

	//allocate a buffer big enough for incoming message
	message = malloc((sizeof(char) * messageSize) + 1);
	memset(message, '\0', (sizeof(char) * messageSize) + 1);

	//loop until message received is as large as expected value
	while (strlen(message) < messageSize)
	{
		memset(buffer, '\0', sizeof(buffer));
		charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
		if (charsRead < 0)
			error("SERVER: ERROR reading from socket\n");
		strcat(message, buffer);
	}
	if (debug)
		fprintf(stderr, "SERVER: I received this from the client: \"%s\"\n", message);

	return message;
}

/*****************************************************************************
Sends the specified message
Reports any error
*****************************************************************************/
void sendMessage(int socketFD, char *message)
{
	int charsWritten;
	int messageSize = strlen(message);

	//send the length of the actual message first as INT
	charsWritten = send(socketFD, &messageSize, sizeof(int), 0);
	if (charsWritten < 0)
		error("CLIENT: ERROR writing to socket\n");
	if (charsWritten < sizeof(int))
		printf("CLIENT: WARNING: Not all data written to socket!\n");

	//then send actual message
	charsWritten = send(socketFD, message, strlen(message), 0);
	if (charsWritten < 0)
		error("CLIENT: ERROR writing to socket\n");
	if (charsWritten < strlen(message))
		printf("CLIENT: WARNING: Not all data written to socket!\n");
}

/*****************************************************************************
Receives a specified message from a client and sends ack to confirm
*****************************************************************************/
char *receiveData(int socketFD)
{
	char *data = receiveMessage(socketFD);
	sendAck(socketFD);
	return data;
}

/*****************************************************************************
Sends a specified message, and receives ACK back
*****************************************************************************/
void sendData(int socketFD, char *message)
{
	sendMessage(socketFD, message);
	recvAck(socketFD);
}

/*****************************************************************************
First receives client connection information
Responds with whether Client is accepted or not
*****************************************************************************/
int verifyClient(int socketFD)
{
	int isVerified;
	char *status;
	char *client;
	char *allowedClient = "OTP_ENC\0";
	char *reject = "REJECT\0";
	char *success = "ACCEPT\0";

	client = receiveMessage(socketFD);

	if (strcmp(client, allowedClient))
	{
		status = reject;
		isVerified = 0;
	}
	else
	{
		status = success;
		isVerified = 1;
	}

	sendMessage(socketFD, status);
	free(client);
	return isVerified;
}

/*****************************************************************************
Converts a valid char into the corresponding INT for encryption
*****************************************************************************/
int cipherCharToInt(char c)
{
	int x;

	if (c == ' ')
		x = MAXCIPHER - 1;
	else
		x = c - 'A';
	return x;
}

/*****************************************************************************
Converts a valid int into the corresponding char for encryption
*****************************************************************************/
char cipherIntToChar(int x)
{
	char c;

	if (x == MAXCIPHER - 1)
		c = ' ';
	else
		c = x + 'A';
	return c;
}

/*****************************************************************************
Takes in a message and key
Performs parameter checking to verify validity of message/key length
Then converts message into ciphertext with key
*****************************************************************************/
char *encryptData(char *message, char *key)
{
	//check key is shorter than message
	if (strlen(key) < strlen(message))
		error("Message is too short compared to Key");

	//encrypt message with key
	//perform addition + modulo to encrypt
	char *encrypted = malloc(sizeof(char) * strlen(message));
	memset(encrypted, '\0', (sizeof(char) * strlen(message)));
	for (int i = 0; i < strlen(message); i++)
	{
		int cipher = cipherCharToInt(message[i]);
		cipher += cipherCharToInt(key[i]);
		cipher %= MAXCIPHER;
		encrypted[i] = cipherIntToChar(cipher);
	}

	return encrypted;
}

/*****************************************************************************
Creates an connection socket for each client. Managed by child processes.
*****************************************************************************/
void processClient(int listenSocketFD)
{
	int establishedConnectionFD;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in clientAddress;

	//clean up any finished connections
	reapZombies();

	// Accept a connection, blocking if one is not available until one connects
	sizeOfClientInfo = sizeof(clientAddress);
	establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
	if (establishedConnectionFD < 0)
		error("ERROR on accept");

	pid_t spawnPid = -5;
	spawnPid = fork();
	switch (spawnPid)
	{
	//error when forking
	case -1:
		fprintf(stderr, "MAJOR FORK ERROR, ABORT ABORT! \n");
		exit(1);
		break;

	//Child Fork
	case 0:
		//process plaintext and key, if client is allowed
		if (verifyClient(establishedConnectionFD))
		{
			char *plaintext = receiveData(establishedConnectionFD);
			char *key = receiveData(establishedConnectionFD);
			char *encrypted = encryptData(plaintext, key);
			sendData(establishedConnectionFD, encrypted);

			free(plaintext);
			free(key);
			free(encrypted);
		}
		close(establishedConnectionFD);
		exit(0);
		break;

	//Parent fork, store data of current connection for future reaping
	default:
		backgroundPIDs.data[backgroundPIDs.count] = spawnPid;
		backgroundPIDs.count++;
		break;
	}
}

/*****************************************************************************
Main Driver
*****************************************************************************/
int main(int argc, char *argv[])
{
	int listenSocketFD;
	int portNumber;
	initBackgroundPIDs();

	if (argc < 2)
	{
		fprintf(stderr, "USAGE: %s port\n", argv[0]);
		exit(1);
	}

	portNumber = atoi(argv[1]);
	listenSocketFD = createListenSocket(portNumber);
	while (1)
	{
		processClient(listenSocketFD);
	}
	close(listenSocketFD);

	return 0;
}
