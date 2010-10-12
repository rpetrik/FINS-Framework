/*
 * TTCP_listen.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */

/*
 * Passive open: listen for a connection on a particular port
 */
//void tcp_Listen(tcp_Socket *s, WORD port, procref datahandler, DWORD timeout)
void TTCP_listen(tcp_Socket *s, WORD port, DWORD timeout)
{
	s->state = tcp_StateLISTEN;
	if ( timeout == 0 ) s->timeout = 0x7ffffff; /* forever... */
	else s->timeout = timeout;
	s->myport = port;
	s->hisport = 0;
	s->seqnum = 0;
	s->dataSize = 0;
	s->flags = 0;
	s->unhappy = 0;
	//s->dataHandler = datahandler;
//	s->dataHandler = (void *)test_dataHandler( (tcp_Socket *)s, (BYTE *)0, (WORD)0);

	s->next = tcp_allsocs;
	tcp_allsocs = s;
}
