#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "bstrlib.h"
#define _XOPEN_SOURCE
#include <unistd.h>

void error(char *message, char *extra)
{
	printf(message, extra);
	exit(1);
}

int main(int argc, char *argv[])
{
	FILE *dictionary = NULL;
	char *hash;
	bstring word = NULL;
	bstring salt = blk2bstr(argv[2], 2); // set salt to be the first 2 characters of the hashed password
	bstring password = bfromcstr(argv[2]);
	
	if(argc < 2)
		error("Usage: %s <dictionary file> <password hash>\n", argv[0]);
	
	printf("%s\n", salt->data); // print salt to confirm it worked
	
	if((dictionary = fopen(argv[1], "r")) == NULL ) // open dictionary file
		error("Couldn't open \'%s\'.\n", argv[1]);
		
	while((word = bgets((bNgetc) fgetc, dictionary, '\n')) != NULL ) { // get each word
		hash = crypt((const char *) word, (const char *) salt); // hash each word with the salt
		printf((char *) hash); // print the hashed word
		
		if(bstricmp((const_bstring) hash, password) == 0) { // compare the hashed word to the hashed password
			printf("Password found:");
			printf((char *) word->data);
			fclose(dictionary);
			bdestroy((bstring) word);
			bdestroy((bstring) salt);
			bdestroy(password);
			exit(0);
		}
	}
	printf("Password not in dictionary.\n");
	fclose(dictionary);
	bdestroy((bstring) word);
	bdestroy((bstring) salt);
	bdestroy(password);
	
	return 0;
}
