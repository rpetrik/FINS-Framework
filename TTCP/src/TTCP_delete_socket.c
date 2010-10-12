/*
 * TTCP_delete_socket.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 *
 * delete a socket from the socket list, if it's there
 */
void TTCP_delete_socket(tcp_Socket *ds)
{
	tcp_Socket *s, **sp;

	sp = &tcp_allsocs;
	for (;;) {
		s = *sp;
		if ( s == ds ) {
			*sp = s->next;
			break;
		}
		if ( s == NIL ) break;
		sp = &s->next;
	}
}
