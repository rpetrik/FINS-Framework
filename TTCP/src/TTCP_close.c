/*
 * TTCP_close.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */
#ifndef WARNING
void TTCP_close(tcp_Socket *s)
{
	if ( s->state == tcp_StateESTAB || s->state == tcp_StateSYNREC ) {
		s->flags = tcp_FlagACK | tcp_FlagFIN;
		s->state = tcp_StateFINWT1;
		s->unhappy = true;
		tcp_Send(s);
	}
}
#endif
