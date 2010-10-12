/*
 * TTCP_write.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado

 * Writes data to a connection.
 * Returns number of bytes written, == 0 when connection is not in
 * established state.
 */
//void tcp_Write( tcp_Socket *s, BYTE *dp, WORD len )
WORD TTCP_write( tcp_Socket *s, BYTE *dp, WORD len )
{
	WORD x;

	if ( s->state != tcp_StateESTAB ) len = 0;
	if ( len > (x = tcp_MaxData - s->dataSize) ) len = x;
	if ( len > 0 ) {
		Move(dp, &s->datas[s->dataSize], len);
		s->dataSize += len;
		tcp_Flush(s);
	}

	return ( len );
}
