// This is the server
#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* Windows XP */
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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
#include <netinet/in.h>
#include <netdb.h>  /* Needed for getaddrinfo() and freeaddrinfo() */
#include <unistd.h> /* Needed for close() */
#endif



#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fcntl.h>


#define SERVER "127.0.0.1"  //ip address of udp server
#define BUFLEN 1024  //Max length of buffer
#define PORT 8888   //The port on which to listen for incoming data
#define UDPHEADERLEN 2 // 2 bytes for our udp portion of the handshake header
#define MODIFIED_UDPHEADERLEN 4 // 4 bytes for our udp portion of the handshake header (to work with old software)
#define PAYLOADOFFSET 8 // 8 bytes for our handshake header
#define MAXPAYLOADLENGTH 1000 // Sets the size of the payload at 1000
#define PACKETIDOFFSET 4 // 4 bytes for the packet ID
#define MAX_PASSWORD_LENGTH 52
#define CHUNK 1000 /* read 1000 bytes at a time */

/* minimum required number of parameters */
#define MIN_REQUIRED 4
/* display usage */
int help() {
	printf("Usage: Server_handshake [SERVER_PORT][PASSWORD][PATH_TO_FILE] \n");
	return 1;
}

int sockInit(void) {
#ifdef _WIN32
	{
		//Initialise winsock
		printf("\nInitialising Winsock...");
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
		printf("\nClosing Winsock...");
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
	struct sockaddr_in myaddr;      /* our address */
	struct sockaddr_in remaddr;     /* remote address */
	socklen_t addrlen = sizeof(remaddr);            /* length of addresses */
	int fd;                         /* our socket */
	unsigned char buf[BUFLEN];     /* receive buffer */

	// INPUT VALIDATION
	if (argc < MIN_REQUIRED) {
		return help();
	}

	// FOR THE SHA1 hash
	FILE *f;
	size_t filelen;
	unsigned char filebuffer[BUFSIZ];
	f = fopen(argv[3], "r");
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

	//EVP_DigestUpdate(mdctx, mess1, strlen(mess1)); // FROM THE EXAMPLE
	//EVP_DigestUpdate(mdctx, mess2, strlen(mess2));

	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	printf("File Digest is: ");
	for (i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
	printf("\n");

	/* Call this once before exit. */
	EVP_cleanup();
	fclose(f);

	sockInit();
	int passwordattempts = 0;
	char udppacket[1024] = { 0 };
	char passwordstorage[MAX_PASSWORD_LENGTH] = { 0 };
	char * password1 = NULL;
	char * passwordreceived = NULL;
	char * payload = udppacket + PAYLOADOFFSET;
	unsigned int * packetID = udppacket + PAYLOADOFFSET;
	password1 = argv[2];
	unsigned int * payloadlenP = NULL;
	short * headerformatP = udppacket;
	char * datapacketP = udppacket + PAYLOADOFFSET + PACKETIDOFFSET;
	for (int i = 0; i < strlen(password1); i++)
	{
		passwordstorage[i] = password1[i];
	}
	passwordstorage[strlen(password1)] = '\0';
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket");
		return 0;
	}

	memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(PORT);


	if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("bind failed");
		return 0;
	}
	puts("Bind done");

	//keep listening for data
	while (1)
	{
		passwordattempts = 0;
		printf("Waiting for JOIN_REQ...\n");
		fflush(stdout);
		//clear the buffer by filling null, it might have previously received data
		memset(buf, '\0', BUFLEN);
		//try to receive some data, this is a blocking call
		int recbytes = recvfrom(fd, buf, BUFLEN, 0, (struct sockaddr *)&remaddr, &addrlen);
		if (recbytes < 0)
		{
			perror("recvfrom() failed");
			exit(EXIT_FAILURE);
		}
		//print details of the client/peer and the data received
		printf("Received packet from %s:%d\n", inet_ntoa(remaddr.sin_addr), ntohs(remaddr.sin_port));
		headerformatP = buf;
		printf("Received message type: %d\n", ntohs(*headerformatP));
		if (ntohs(*headerformatP) == 1)
		{
			printf("Received JOIN_REQ, sending PASSWD_REQ...\n");
			while (passwordattempts < 3)
			{
				headerformatP = udppacket;
				payloadlenP = udppacket + MODIFIED_UDPHEADERLEN;
				*payloadlenP = htons(0);
				*headerformatP = htons(2);
				int sentbytes = sendto(fd, udppacket, PAYLOADOFFSET, 0, (struct sockaddr*)&remaddr, addrlen);
				if (sentbytes < 0)
				{
					perror("sendto() failed");
					exit(EXIT_FAILURE);
				}
				//clear the buffer by filling null, it might have previously received data
				memset(buf, '\0', BUFLEN);
				//try to receive some data, this is a blocking call
				recbytes = recvfrom(fd, buf, BUFLEN, 0, (struct sockaddr *)&remaddr, &addrlen);
				if (recbytes < 0)
				{
					perror("recvfrom() failed");
					exit(EXIT_FAILURE);
				}
				//print details of the client/peer and the data received
				printf("\nReceived packet from %s:%d\n", inet_ntoa(remaddr.sin_addr), ntohs(remaddr.sin_port));

				headerformatP = buf;
				//printf("Header data: %d\n", buf[1]);
				printf("Received message type: %d\n", ntohs(*headerformatP));
				printf("Received PASSWD_RESP...checking password...\n");
				if (ntohs(*headerformatP) == 3)
				{
					passwordreceived = buf + PAYLOADOFFSET;
					payloadlenP = buf + MODIFIED_UDPHEADERLEN;
					/************************** FOR DEBUGGING **************
					printf("The password length is %lu\n", ntohl(*payloadlenP));
					printf("\nStored password is: ");
					for (int i = 0; i < ntohl(*payloadlenP); i++)
					{
						printf("%c", passwordstorage[i]);
					}
					printf("\nReceived password is: ");
					for (int i = 0; i < ntohl(*payloadlenP); i++)
					{
						printf("%c", passwordreceived[i]);
					}
					************************** FOR DEBUGGING ***************/
					if (strcmp(passwordreceived, passwordstorage) == 0)
					{
						printf("\nPassword correct!\n");
						printf("Beginning file transfer...");
						headerformatP = udppacket;
						payloadlenP = udppacket + MODIFIED_UDPHEADERLEN;
						*headerformatP = htons(4);
						// SEND THE PASSWORD ACCEPT PACKET
						sentbytes = sendto(fd, udppacket, PAYLOADOFFSET, 0, (struct sockaddr*)&remaddr, addrlen);
						if (sentbytes < 0)
						{
							perror("sendto() failed");
							exit(EXIT_FAILURE);
						}
						// ************* CODE TO TRANSFER FILE FOLLOWS>>>

						f = fopen(argv[3], "r");
						if (!f) {
							fprintf(stderr, "couldn't open %s\n", argv[3]);
							return 1;
						}
						size_t nread;
						// SET PACKET ID
						headerformatP = udppacket;
						*headerformatP = htons(5);
						*packetID = htonl(1);
						if (f)
						{
							while ((nread = fread(datapacketP, 1, CHUNK, f)) > 0)
								// SEND THE DATA PACKETS
							{
								*payloadlenP = htonl(nread);
								sentbytes = sendto(fd, udppacket, PAYLOADOFFSET + PACKETIDOFFSET + CHUNK, 0, (struct sockaddr*)&remaddr, addrlen);
								//fwrite(datapacketP, 1, nread, stdout); // FOR DEBUGGING
								memset(payload + PACKETIDOFFSET, '\0', MAXPAYLOADLENGTH); // Clears the payload in preparation for the next one (saves room for the packet id)
								// INCREMENT THE PACKET ID COUNT
								*packetID = htonl((ntohl(*packetID)) + 1);
							}
							if (ferror(f))
							{
								/* deal with error */
							}
							fclose(f);
						}
						// SEND THE DIGEST IN THE TERMINATE PACKET
						*headerformatP = htons(6);
						for (i = 0; i < md_len; i++)
						{
							*(payload + i) = md_value[i];
						}
						*payloadlenP = htonl(md_len);
						sentbytes = sendto(fd, udppacket, PAYLOADOFFSET + md_len, 0, (struct sockaddr*)&remaddr, addrlen);
						break;
					}
					else
					{
						passwordattempts++;
						if (passwordattempts == 3)
						{
							// SEND REJECT PACKET
							headerformatP = udppacket;
							payloadlenP = udppacket + MODIFIED_UDPHEADERLEN;
							*payloadlenP = htons(0);
							*headerformatP = htons(7);
							int sentbytes = sendto(fd, udppacket, PAYLOADOFFSET, 0, (struct sockaddr*)&remaddr, addrlen);
							printf("3 failed logins, shutting down...\nABORT ABORT\n\n");
							return 0;
						}
						continue;
					}
				}
			}
		}
		else
		{
			printf("Received request out of order, shutting down...\nABORT ABORT\n\n");
		}
		printf("File transfer complete!\nOK OK\n\n");
	}
	closeAndClean(fd);
	return 0;
}