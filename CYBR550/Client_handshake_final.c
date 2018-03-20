// This is the client
#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* Windows XP */
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
WSADATA wsa;
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#else
/* Assume that any non-Windows platform uses POSIX-style sockets instead. */
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>  /* Needed for getaddrinfo() and freeaddrinfo() */
#include <unistd.h> /* Needed for close() */
#endif

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

//#define SERVER "127.0.0.1"  //ip address of udp server
#define BUFLEN 1024  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
#define UDPHEADERLEN 2 // 2 bytes for our udp portion of the handshake header
#define MODIFIED_UDPHEADERLEN 4 // 4 bytes for our udp portion of the handshake header (to work with old software)
#define PAYLOADOFFSET 8 // 8 bytes for our handshake header
#define MAX_PASSWORD_SIZE 52 // max 52 bytes for a password payload
#define CHUNK 1000 /* read 1000 bytes at a time */
#define PACKETIDOFFSET 4 // 4 bytes for the packet ID

/* minimum required number of parameters */
#define MIN_REQUIRED 4
/* display usage */
int help() {
	printf("Usage: Client_handshake [SERVER_ADDRESS][SERVER_PORT][PASSWORD1][PASSWORD2][PASSWORD3][PATH_TO_SAVE_FILE] \n");
	return 1;
}

int sockInit(void) {
#ifdef _WIN32
	{
		//Initialise winsock
		printf("Initialising Winsock...");
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			printf("Failed. Error Code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		printf("Initialised.\n");
		return 0;
	}
#else
	{
		return 0;
	}
#endif
}

int closeAndClean(int s)
{
#ifdef _WIN32
	{
		//Initialise winsock
		printf("Closing Winsock...");
		closesocket((SOCKET)s);
		printf("Closed socket.\n");
		WSACleanup();
		printf("WSACleanup performed on socket.\n");
		return 0;
	}
#else
	{
		close(s);
		return 0;
	}
#endif
}

int main(int argc, char *argv[])
{
	int sockfd;
	char buf[BUFLEN];
	char udppacket[1024] = { 0 };
	const char * currentpassword = NULL;
	int passwordattempts = 0;
	unsigned int * payloadlenP = NULL;
	char * payload = udppacket + PAYLOADOFFSET;
	unsigned int * packetID = NULL;
	short * headerformatP = udppacket;
	/* From beej */
	int status;
	struct addrinfo hints;
	struct addrinfo *servinfo, *p; // will point to the results
	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;
	int slen;
	int recbytes;

	// INPUT VALIDATION 
	if (argc < MIN_REQUIRED) {
		return help();
	}

	sockInit();

	if ((status = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		printf("getaddrinfo failed with error: %d\n", status);
		exit(1);
	}
	// servinfo now points to a linked list of 1 or more struct addrinfos
	// ... do everything until you don't need servinfo anymore ....
	//Initialise winsock

	//create socket
	//if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
	// loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			perror("client: socket");
			continue;
		}
		//connect! (might not be necessary for UDP)
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			closeAndClean(sockfd);
			perror("client: connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	//start communication
	//while (1)
	//{
	printf("Sending JOIN_REQ...\n");
	slen = (int)p->ai_addrlen;
	//send the message
	*headerformatP = htons(1); // Need to swap bytes using htons
	int sentbytes = sendto(sockfd, udppacket, PAYLOADOFFSET, 0, p->ai_addr, slen);
	if (sentbytes < 0)
	{
		//printf("sendto() failed with error code : %d", WSAGetLastError()); // get rid of WINDOWS errors
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	}
	while (passwordattempts < 4)
	{
		//receive a reply and print it
		//clear the buffer by filling null, it might have previously received data
		memset(buf, '\0', BUFLEN);
		//try to receive some data, this is a blocking call
		recbytes = recvfrom(sockfd, buf, BUFLEN, 0, p->ai_addr, &(p->ai_addrlen));
		if (recbytes < 0)
		{
			//printf("recvfrom() failed with error code : %d", WSAGetLastError());
			perror("recvfrom() failed");
			exit(EXIT_FAILURE);
		}
		headerformatP = buf;
		printf("Received message type: %d\n", ntohs(*headerformatP));
		// IF PASSWD_REQ IS RECEIVED

		if (ntohs(*headerformatP) == 2)
		{
			// THIS CODE LOADS UP A NEW PASSWORD
			currentpassword = argv[passwordattempts + 3];
			// Zero out the password payload
			for (int i = 0; i < MAX_PASSWORD_SIZE; i++)
			{
				*(payload + i) = '\0';
			}
			// Fill in the new password
			for (int i = 0; i < strlen(currentpassword); i++)
			{
				*(payload + i) = currentpassword[i];
			}
			//**************************************************
			headerformatP = udppacket;
			*headerformatP = htons(3);
			payloadlenP = udppacket + MODIFIED_UDPHEADERLEN;
			*payloadlenP = htonl(strlen(currentpassword)); // Need to swap bytes 
			printf("Received PASSWD_REQ...\n");
			printf("Transmitting PASSWD_RESP...\n");
			passwordattempts++;
			sentbytes = sendto(sockfd, udppacket, PAYLOADOFFSET + MAX_PASSWORD_SIZE, 0, p->ai_addr, slen);
			if (sentbytes < 0)
			{
				//printf("sendto() failed with error code : %d", WSAGetLastError());
				perror("sendto() failed");
				exit(EXIT_FAILURE);
			}
		}
		// IF ACCEPT IS RECEIVED
		else if (ntohs(*headerformatP) == 4)
		{
			break;
		}
		// IF REJECT IS RECEIVED
		else
		{
			printf("Incorrect password, shutting down...\nABORT ABORT\n\n");
			closeAndClean(sockfd);
			freeaddrinfo(servinfo); // free the linked-list
			return 0;
		}
	}
	printf("Ready to receive file...\n");
	FILE *f;
	size_t nwrite, nread;
	f = fopen(argv[6], "w");
	if (!f) {
		fprintf(stderr, "couldn't open %s\n", argv[6]);
		return 1;
	}
	//RECEIVE DATA 
	headerformatP = buf;
	payload = buf + PAYLOADOFFSET + PACKETIDOFFSET;
	packetID = buf + PAYLOADOFFSET;
	payloadlenP = buf + MODIFIED_UDPHEADERLEN;
	unsigned int packetSequence = 1;
	do	{
		memset(buf, '\0', BUFLEN);
		recbytes = recvfrom(sockfd, buf, BUFLEN, 0, p->ai_addr, &(p->ai_addrlen));
		if (recbytes < 0)
		{
			//printf("recvfrom() failed with error code : %d", WSAGetLastError());
			perror("recvfrom() failed");
			exit(EXIT_FAILURE);
		}
		if (*headerformatP == htons(6)) // FILE IS DONE TRANSFERRING
			break;
		if (packetSequence == ntohl(*packetID)) // Verify the packet sequence
		{
			nwrite = fwrite(payload, 1, ntohl(*payloadlenP), f);
			//fwrite(payload, 1, nwrite, stdout); // For debugging
			if (ferror(f))
			{
				/* deal with error */
			}
		}
		else
		{
			printf("Received transmission out of order, quitting...\nABORT ABORT\n\n");
			closeAndClean(sockfd);
			freeaddrinfo(servinfo); // free the linked-list
			return 0;
		}

		packetSequence++;
	} while (*headerformatP == htons(5)); // WHILE "DATA" packets are coming in
	fclose(f);

	// THIS IS TO SET THE PAYLOAD POINTER AT THE DIGEST
	payload = buf + PAYLOADOFFSET;
	
	//VERIFY SHA1 (COMPARE TO DIGEST)
	printf("\nReceived Digest is     : ");
	for (int i = 0; i < ntohl(*payloadlenP); i++)

		printf("%02x", (unsigned char)payload[i]);
	printf("\n");

	// FOR THE SHA1 hash
	size_t filelen;
	unsigned char filebuffer[BUFSIZ];
	f = fopen(argv[6], "r");
	if (!f) {
		fprintf(stderr, "couldn't open %s\n", argv[3]);
		return 1;
	}
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	//char mess1[] = "Test Message\n"; // FROM EXAMPLE
	//char mess2[] = "Hello World\n"; // FROM EXAMPLE
	char line[128]; /* or some other suitable maximum line size */
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("sha1");

	if (!md) {
		printf("Unknown message digest %s\n", "sha1");
		exit(1);
	}

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);

	// READS THE INPUT FILE LINE BY LINE AND HASHES (SHA1)
	while (fgets(line, sizeof line, f) != NULL) {
		EVP_DigestUpdate(mdctx, line, strlen(line));
	}

	//EVP_DigestUpdate(mdctx, mess1, strlen(mess1)); // FROM EXAMPLE
	//EVP_DigestUpdate(mdctx, mess2, strlen(mess2));

	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	printf("Calculated Digest is   : ");
	for (i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
	printf("\n");

	/* Call this once before exit. */
	EVP_cleanup();
	fclose(f);
	//}

	// Verify the SHA1 SUM
	for (i = 0; i < ntohl(*payloadlenP); i++)
	{
		if ((unsigned char)payload[i] != md_value[i])
		{
			printf("File integriy failed...\nABORT ABORT\n\n");
			return 0;
		}
	}
	printf("File integrity success!\nOK OK\n\n");

	closeAndClean(sockfd);

	freeaddrinfo(servinfo); // free the linked-list
	return 0;
}