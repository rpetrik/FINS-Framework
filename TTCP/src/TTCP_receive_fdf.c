/*
 * TTCP_receive_fdf.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 *
 *
 */
void TTCP_receive_fdf( in_Header *ip )
{
	tcp_Header *tp;
	tcp_PseudoHeader ph;
	WORD len;
	BYTE *dp;
	WORD x, diff;
	tcp_Socket *s;
	WORD flags;

	len = in_GetHdrlenBytes(ip);
	tp = (tcp_Header *)((BYTE *)ip + len);
	len = ip->length - len;

	/* demux to active sockets */
	for ( s = tcp_allsocs; s; s = s->next )
		if ( s->hisport != 0 &&
		tp->dstPort == s->myport &&
		tp->srcPort == s->hisport &&
		ip->source == s->hisaddr ) break;
	if ( s == NIL ) {
		/* demux to passive sockets */
		for ( s = tcp_allsocs; s; s = s->next )
		if ( s->hisport == 0 && tp->dstPort == s->myport ) break;
	}
	if ( s == NIL ) {
		tcp_Reset( ip, tp );
#ifdef DEBUG
		if ( tcp_logState & tcp_LOGPACKETS ) tcp_DumpHeader(ip, tp, "Discarding");
#endif
		return;
	}

#ifdef DEBUG
	if ( tcp_logState & tcp_LOGPACKETS )
		tcp_DumpHeader(ip, tp, "Received");
#endif

	/* save his ethernet address */
	Move(&((((eth_Header *)ip) - 1)->source[0]), &s->hisethaddr[0], sizeof(eth_HwAddress));

	ph.src = ip->source;
	ph.dst = ip->destination;
	ph.mbz = 0;
	ph.protocol = 6;
	ph.length = len;
	ph.checksum = checksum((WORD *)tp, len);
	if ( checksum((WORD *)&ph, sizeof ph) != 0xFFFF )
	{
#ifdef DEBUG
		print("bad tcp checksum, received anyway\r\n");
#endif
	}

	flags = tp->flags;
	if ( flags & tcp_FlagRST ) {
#ifdef DEBUG
		print("connection reset\r\n");
#endif
		s->state = tcp_StateCLOSED;
//		s->dataHandler((tcp_Socket *)s,(BYTE*) 0, (WORD *)-1);
		DATAHANDLER((tcp_Socket *)s,(BYTE*) 0,-1);
		tcp_Unthread(s);
		return;
	}

	switch ( s->state ) {
		case tcp_StateLISTEN:
			if ( flags & tcp_FlagSYN ) {
				s->acknum = tp->seqnum + 1;
				s->hisport = tp->srcPort;
				s->hisaddr = ip->source;
				s->flags = tcp_FlagSYN | tcp_FlagACK;
				tcp_Send(s);
				s->state = tcp_StateSYNREC;
				s->unhappy = true;
				s->timeout = tcp_TIMEOUT;
#ifdef DEBUG
				print("Syn from 0x%x#%d (seq 0x%x)\r\n", s->hisaddr, s->hisport, tp->seqnum);
#endif
	        	}
			break;

		case tcp_StateSYNSENT:
			if ( flags & tcp_FlagSYN ) {
				s->acknum++;
				s->flags = tcp_FlagACK;
				s->timeout = tcp_TIMEOUT;
				if ( (flags & tcp_FlagACK) && tp->acknum == (s->seqnum + 1) ) {
#ifdef DEBUG
					print("Open\r\n");
#endif
					s->state = tcp_StateESTAB;
					s->seqnum++;
					s->acknum = tp->seqnum + 1;
					s->unhappy = false;
				} else {
					s->state = tcp_StateSYNREC;
				}
			}
			break;

		case tcp_StateSYNREC:
			if ( flags & tcp_FlagSYN ) {
				s->flags = tcp_FlagSYN | tcp_FlagACK;
				tcp_Send(s);
				s->timeout = tcp_TIMEOUT;
#ifdef DEBUG
				print(" retransmit of original syn\r\n");
#endif
			}
			if ( (flags & tcp_FlagACK) && tp->acknum == (s->seqnum + 1) ) {
				s->flags = tcp_FlagACK;
				tcp_Send(s);
				s->seqnum++;
				s->unhappy = false;
            			s->state = tcp_StateESTAB;
				s->timeout = tcp_TIMEOUT;
#ifdef DEBUG
				print("Synack received - connection established\r\n");
#endif
			}
			break;

		case tcp_StateESTAB:
			if ( (flags & tcp_FlagACK) == 0 ) return;
			/* process ack value in packet */
			diff = tp->acknum - s->seqnum;
			if ( diff > 0 ) {
				Move(&s->datas[diff], &s->datas[0], diff);
				s->dataSize -= diff;
				s->seqnum += diff;
			}
			s->flags = tcp_FlagACK;
			tcp_ProcessData(s, tp, len);
			break;

		case tcp_StateFINWT1:
			if ( (flags & tcp_FlagACK) == 0 ) return;
			diff = tp->acknum - s->seqnum - 1;
			s->flags = tcp_FlagACK | tcp_FlagFIN;

			/*
			 * This is modified by Jun-Ku.
			 * If we send data and it's unacked. then send FIN. the receiver send diff = dataSize+1 (and it's ACK on FIN ).
			 * if ( diff == 0 ) {
			 */

			if ( diff == 0 || diff == s->dataSize ) {
				s->state = tcp_StateFINWT2;
				s->flags = tcp_FlagACK;
				s->seqnum += (diff+1);
				s->dataSize -= diff;
#ifdef DEBUG
				print("finack received.\r\n");
#endif
			}

			tcp_ProcessData(s, tp, len);
			break;

		case tcp_StateFINWT2:
			s->flags = tcp_FlagACK;
			tcp_ProcessData(s, tp, len);
			break;

		case tcp_StateCLOSING:
			if ( tp->acknum == (s->seqnum + 1) ) {
				s->state = tcp_StateTIMEWT;
				s->timeout = tcp_TIMEOUT;
			}
			break;

		case tcp_StateLASTACK:
			if ( tp->acknum == (s->seqnum + 1) ) {
				s->state = tcp_StateCLOSED;
				s->unhappy = false;
				s->dataSize = 0;
//				s->dataHandler((tcp_Socket *)s,(BYTE *)0, (WORD *)0);
				DATAHANDLER((tcp_Socket *)s,(BYTE *)0,0);
				tcp_Unthread(s);
#ifdef DEBUG
				print("Closed.    \r\n");
#endif
			} else {
				s->flags = tcp_FlagACK | tcp_FlagFIN;
				tcp_Send(s);
				s->timeout = tcp_TIMEOUT;
#ifdef DEBUG
				print("retransmitting FIN\r\n");
#endif
			}
			break;

		case tcp_StateTIMEWT:
			s->flags = tcp_FlagACK;
			tcp_Send(s);
	}
}
