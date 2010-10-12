/*
 * TTCP_reject.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */
/*
 * Reject tcp connection
 */

void TTCP_reject(tcp_Socket *s)
{
	if ( s->state != tcp_StateLISTEN && s->state != tcp_StateCLOSED ) {
		s->flags = tcp_FlagRST | tcp_FlagACK;
		tcp_Send(s);
	}
	s->unhappy = 0;
	s->dataSize = 0;
	s->state = tcp_StateCLOSED;
//	s->dataHandler((tcp_Socket*)s,(BYTE *)0, (WORD *)-1);
	DATAHANDLER( (tcp_Socket *)s,(BYTE *)0, (WORD *)0 ) ;

//	s->dataHandler(0,0,0);
	tcp_Unthread(s);
}


