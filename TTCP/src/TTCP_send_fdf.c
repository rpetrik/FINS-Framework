/*
 * TTCP_send_fdf.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 */

void TTCP_send_fdf(tcp_Socket *s)
{
	tcp_PseudoHeader ph;
	struct _pkt {
		in_Header in;
		tcp_Header tcp;
		DWORD maxsegopt;
	} *pkt;
	BYTE *dp;

	pkt = (struct _pkt *)sed_FormatPacket(&s->hisethaddr[0], 0x800);
	dp = (BYTE *)&pkt->maxsegopt;

	pkt->in.length = sizeof(in_Header) + sizeof(tcp_Header) + s->dataSize;

	/* tcp header */
	pkt->tcp.srcPort = s->myport;
	pkt->tcp.dstPort = s->hisport;
	pkt->tcp.seqnum = s->seqnum;
	pkt->tcp.acknum = s->acknum;
	pkt->tcp.window = 1024;
	pkt->tcp.flags = s->flags | 0x5000;		/* Header length = 20bytes ;; no option */
	pkt->tcp.checksum = 0;
	pkt->tcp.urgentPointer = 0;
	if ( s->flags & tcp_FlagSYN ) {
		pkt->tcp.flags += 0x1000;
		pkt->in.length += 4;
		pkt->maxsegopt = 0x02040578; /* 1400 bytes */
		dp += 4;
	}
	Move(s->datas, dp, s->dataSize);		/* copy data to pointer which is next to tcp header */

	/* internet header */
	pkt->in.vht = 0x4500;   /* version 4, hdrlen 5, tos 0 */
	pkt->in.identification = tcp_id++;
	pkt->in.frag = 0;
	pkt->in.ttlProtocol = (250<<8) + 6;
	pkt->in.checksum = 0;
	pkt->in.source = sin_lclINAddr;
	pkt->in.destination = s->hisaddr;
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
