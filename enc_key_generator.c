/*****************************************************************************
keygen.c
Author: Daniel Meirovitch
Date: May 22 2019

Description: Generates a keyfile with a command-line specified length.
Key file is printed to stdout and only only uses Capital Letters + Space

Intended Usage:
keygen <keylength>
*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	//confirm number of arguments
	if(argc != 2)
	{
		printf("Improper number of Command Line Arguments\n");
		exit(1);
	}

	//set random seed and prepare random string
	srand(time(0));
	int keyLength = atoi(argv[1]);
	char* key = (char*) malloc((keyLength+1)*sizeof(char));
	memset(key, '\0', sizeof(char)*(keyLength+1));

	//loop through and assign random letters to string
	for(int i = 0; i < keyLength; i++)
	{
		char randLetter;
		int randomInc = rand() % 27;
		if(randomInc == 26)
			randLetter = ' ';
		else
			randLetter = 'A' + randomInc;

		key[i] = randLetter;
	}

	printf("%s\n", key);
	free(key);
}