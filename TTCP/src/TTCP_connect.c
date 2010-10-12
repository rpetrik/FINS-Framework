/*
 * TTCP_connect.c
 *
 *  Created on: Jul 30, 2010
 *      Author: rado
 */
#include "TTCP.h"

void TTCP_connect(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len){

	int s;
	struct sockaddr_in myaddr;
	// pretend the server is at 63.161.169.137 listening on port 80:

	myaddr.sin_family = AF_INET;
	myaddr.sin_port = htons(80);
	inet_aton("193.200.9.209", &myaddr.sin_addr);

	s = socket(PF_INET, SOCK_STREAM, 0);
	connect(s, (struct sockaddr*)&myaddr, sizeof(myaddr));
	PRINT_DEBUG("Connect(): %d", connect(s, (struct sockaddr*)&myaddr, sizeof(myaddr)));

	// now we're ready to send() and recv()




}
