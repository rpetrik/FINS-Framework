/*
 * TTCP_reset.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */

/*
 * Format and send an outgoing reset segment
 */
void tcp_Reset( in_Header *ip, tcp_Header *tp )
{
	tcp_PseudoHeader ph;
	struct _pkt {
		in_Header in;
		tcp_Header tcp;
		DWORD maxsegopt;
	} *pkt;

	pkt = (struct _pkt *)sed_FormatPacket(&(((eth_Header *)ip)-1)->source[0], 0x800);
	pkt->in.length = sizeof(in_Header) + sizeof(tcp_Header);

	/* tcp header */
	pkt->tcp.srcPort = tp->dstPort;
	pkt->tcp.dstPort = tp->srcPort;
	pkt->tcp.seqnum = tp->seqnum;
	pkt->tcp.acknum = tp->acknum;
	pkt->tcp.window = 1024;
	pkt->tcp.flags = tcp_FlagRST | 0x5000;		/* Header length = 20bytes ;; no option */
	pkt->tcp.checksum = 0;
	pkt->tcp.urgentPointer = 0;

	/* internet header */
	pkt->in.vht = 0x4500;   /* version 4, hdrlen 5, tos 0 */
	pkt->in.identification = tcp_id++;
	pkt->in.frag = 0;
	pkt->in.ttlProtocol = (250<<8) + 6;
	pkt->in.checksum = 0;
	pkt->in.source = sin_lclINAddr;
	pkt->in.destination = ip->source;
	pkt->in.checksum = ~(checksum((WORD *)&pkt->in, sizeof(in_Header)));

	/* compute tcp checksum */
	ph.src = pkt->in.source;
	ph.dst = pkt->in.destination;
	ph.mbz = 0;
	ph.protocol = 6;
	ph.length = pkt->in.length - sizeof(in_Header);
	ph.checksum = checksum((WORD *)&pkt->tcp, ph.length);
	pkt->tcp.checksum = ~checksum((WORD *)&ph, sizeof ph);

	sed_Send(pkt->in.length);
}
