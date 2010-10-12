/*
 * TCP_checksum.c -  compute a TCP pseudo-header checksum
 *
 *  Created on: Jun 3, 2010
 *      Author: rado
 */

#include "TTCP.h"

unsigned short TCP_checksum(struct tcp_sgm *segment, struct tcp_pseudo_header *pseudo_header, unsigned int len)
{
	uint16_t	*sptr;
	uint32_t 	checksum = 0;
	int			i;


	for (i=0; i<IP4_ALEN; ++i)
		checksum += *sptr++;
	sptr = (unsigned short *)segment;
	checksum += htons(IP4_TCP_ID + len);
	if (len % 2) {
		((char *)segment)[len] = 0;	/* pad*/
		len += 1;	/* for the following division */
	}
	len >>= 1;	/* convert to length in shorts */

	for (i=0; i<len; i++)
		checksum += *sptr++;
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return (unsigned short)(~checksum & 0xffff);
}
