/*
 * TTCP_flush_buffer.c
 *
 *  Created on: Oct 12, 2010
 *      Author: rado
 *
 * Send data currently in the buffer
 */
void tcp_Flush(tcp_Socket *s)
{
    if ( s->dataSize > 0 ) {
        s->flags |= tcp_FlagPUSH;
        tcp_Send(s);
    }
}
