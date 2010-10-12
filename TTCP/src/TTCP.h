/*
 * tcp.h
 *
 *  Created on: Jun 3, 2010
 *      Author: rado
 */

#ifndef TCP_H_
#define TCP_H_
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define DEBUG
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif

/* Constants */
#define	EP_DLEN		1500	 	/* Maximum length of data field in Ethernet packet	*/
#define	IP4_ALEN	4		 	/* IP address length in bytes (octets)				*/
#define	IP4_TCP_ID	6		 	/* protocol type for TCP packets					*/

/* Data type definitions*/
typedef uint32_t 		IP4addr;
typedef unsigned short	tcp_seq;

/* Data structure for describing the segment header fields*/
struct tcp_sgm_header
{
	uint16_t 	sport;	/* source port							*/
	uint16_t 	dport;	/* destination port						*/
	uint32_t	seq;	/* sequence								*/
	uint32_t	ack; 	/* acknowledged sequence				*/
	uint16_t 	hlenflg;/* combined 4b hlen, 6b resrvd, 6b flgs	*/
	uint16_t 	window;	/* window advertisement					*/
	uint16_t 	cksum; 	/* check sum							*/
	uint16_t 	urgptr;	/* urgent pointer						*/
};

/* Data structure for holding TCP header data */
struct tcp_header
{
	uint16_t 	sport;	/* source port							*/
	uint16_t 	dport;	/* destination port						*/
	uint32_t	seq;	/* sequence								*/
	uint32_t	ack; 	/* acknowledged sequence				*/
	uint8_t 	hlen;	/* 4bit header length					*/
	uint8_t		rsrvd;	/* 6bits reserved						*/
	uint8_t		flags;	/* 6bits flags							*/
	uint16_t 	window;	/* window advertisement					*/
	uint16_t 	urgptr;	/* urgent pointer						*/
};
/* struct to hold IP pseudo header*/
struct tcp_pseudo_header
{
	uint32_t	srcadd;
	uint32_t	dstadd;
	uint8_t		zeros;
	uint8_t		protocol;
	uint16_t	length;
};

/* Data structure for holding TCP segment (datagram) */
struct tcp_sgm
{
	struct tcp_sgm_header header;
	uint8_t data[1];
};
/* Transmission control block, holds information about a connection*/
struct tcb {
				short	state;		/* TCP state					*/
				short	ostate;		/* output state					*/
				short	type;		/* TCP type (SERVER, CLIENT)	*/
				int		mutex;		/* tcb mutual exclusion			*/
				short	code;		/* TCP code for next packet		*/
				short	flags;		/* various TCB state flags		*/
				short	error;		/* return error for user side	*/

				IP4addr	rip;		/* remote IP address			*/
	unsigned	short	rport;		/* remote TCP port				*/
				IP4addr	lip;		/* local IP address				*/
	unsigned 	short	lport;		/* local TCP port				*/
				short	*pni; 		/* pointer to our interface		*/

				tcp_seq	suna;		/* send unacked						*/
				tcp_seq	snext;		/* send next						*/
				tcp_seq	slast;		/* sequence of FIN, if TCBF_SNDFIN	*/
	unsigned 	long	swindow;	/* send window size (octets)		*/
				tcp_seq	lwseq;		/* sequence of last window update	*/
				tcp_seq	lwack;		/* ack seq of last window update	*/
	unsigned 	int		cwnd;		/* congestion window size (octets)	*/
	unsigned 	int		ssthresh;	/* slow start threshold (octets)	*/
	unsigned 	int		smss;		/* send max segment size (octets)	*/
				tcp_seq	iss;		/* initial send sequence			*/

				int		srt;		/* smoothed Round Trip Time			*/
				int		rtde;		/* Round Trip deviation estimator	*/
				int		persist;	/* persist timeout value			*/
				int		keep;		/* keepalive timeout value			*/
				int		rexmt;		/* retransmit timeout value			*/
				int		rexmtcount;	/* number of rexmts sent			*/

				tcp_seq	rnext;		/* receive next				*/
				tcp_seq	rupseq;		/* receive urgent pointer	*/
				tcp_seq	supseq;		/* send urgent pointer		*/

				int		lqsize;		/* listen queue size (SERVERs)			*/
				int		listenq;	/* listen queue port (SERVERs)			*/
	struct 		tcb 	*pptcb;		/* pointer to parent TCB (for ACCEPT)	*/
				int		ocsem;		/* open/close semaphore 				*/
				int		dvnum;		/* TCP slave pseudo device number		*/

				int		ssema;		/* send semaphore			*/
	unsigned	char	*sndbuf;	/* send buffer				*/
	unsigned 	int		sbstart;	/* start of valid data		*/
	unsigned 	int		sbcount;	/* data character count		*/
	unsigned 	int		sbsize;		/* send buffer size (bytes)	*/

				int		rsema;		/* receive semaphore					*/
	unsigned	char	*rcvbuf;	/* receive buffer (circular)			*/
	unsigned 	int		rbstart;	/* start of valid data					*/
	unsigned 	int		rbcount;	/* data character count					*/
	unsigned 	int		rbsize;		/* receive buffer size (bytes)			*/
	unsigned 	int		rmss;		/* receive max segment size				*/
				tcp_seq	cwin;		/* seq of currently advertised window	*/
				int		rsegq;		/* segment fragment queue				*/
				tcp_seq	finseq;		/* FIN sequence number, or 0			*/
				tcp_seq	pushseq;	/* PUSH sequence number, or 0			*/
};
/* TCP Control Bits */
#define	TCPF_URG	0x20	/* urgent pointer is valid				*/
#define	TCPF_ACK	0x10	/* acknowledgment field is valid		*/
#define	TCPF_PSH	0x08	/* this segment requests a push			*/
#define	TCPF_RST	0x04	/* reset the connection					*/
#define	TCPF_SYN	0x02	/* synchronize sequence numbers			*/
#define	TCPF_FIN	0x01	/* sender has reached end of its stream	*/

unsigned short TCP_checksum(struct tcp_sgm *segment, struct tcp_pseudo_header *pseudo_header, unsigned int len);
#endif /* TCP_H_ */
