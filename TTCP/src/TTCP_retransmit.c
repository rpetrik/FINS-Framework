/*
 * TTCP_retransmit.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */

/*
 * Checks for packets to be retransmitted
 */
void TTCP_retransmit(void)
{
	tcp_Socket *s;
	BOOL x;

	for ( s = tcp_allsocs; s; s = s->next ) {
		x = false;
		if ( s->dataSize > 0 || s->unhappy ) {	/* if we didn't received ack( dataSize > 0 ) or unhappy, then re-xmit it */
			tcp_Send(s);
			x = true;
		}
		if ( x || s->state != tcp_StateESTAB )
			s->timeout -= tcp_RETRANSMITTIME;
		if ( s->timeout <= 0 ) {
			if ( s->state == tcp_StateTIMEWT ) {
#ifdef DEBUG
				print("Closed.    \r\n");
#endif
				s->state = tcp_StateCLOSED;
//				s->dataHandler((tcp_Socket *)s,(BYTE *)0, (WORD *)0);
				DATAHANDLER((tcp_Socket *)s,(BYTE *)0, 0);
				tcp_Unthread(s);
			} else {
#ifdef DEBUG
				print(" : Timeout, aborting\r\n");
#endif
				tcp_Abort(s);
			}
		}
	}
}
