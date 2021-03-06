#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "bstrlib.h"
#define _XOPEN_SOURCE
#include <unistd.h>

void error(char *message, char *extra) // not sure if needed
{
	printf(message, extra);
	exit(1);
}

int main(int argc, char *argv[])
{
	FILE *dictionary;
	char *hash;
	char word[30];
	bstring salt = blk2bstr(argv[2], 2); // salt is first 2 characters
	bstring password = bfromcstr(argv[2]);
	
	if(argc < 2)
		error("Usage: %s <dictionary file> <password hash>\n", argv[0]);

	printf("%s\n", salt->data); // print salt to confirm
	
	if((dictionary = fopen(argv[1], "r")) == NULL ) // open dictionary file
		error("Couldn't open \'%s\'.\n", argv[1]);
		
	while(fgets(word, 30, dictionary) != NULL ) { // get each word
		bstring bword = bfromcstr(word);
		bassignmidstr(bword, bword, 0, blength(bword) - 1); // cut off the \n from bword
		hash = crypt((const char *) word->data, (const char *) salt->data); // hash each word with the salt
		bstring bhash = bfromcstr(hash);
		//printf("Trying ==> %s\n", bhash->data); // print the hashed word
				
		if(bstrcmp(bhash, password) == 0) { // compare the hashed word to the hashed password
			printf("Password found: %s", word);
			fclose(dictionary);
			bdestroy(bword);
			bdestroy(bhash); // free up allocated memory
			bdestroy(salt);
			bdestroy(password);
			exit(0);
		} else { // fixed a memory leak with the bhash in the while-loop
			bdestroy(bword);
			bdestroy(bhash);
		}
	
	}
	printf("Password not in dictionary.\n");
	fclose(dictionary);
	bdestroy(salt);
	bdestroy(password);
	
	return 0;
}
