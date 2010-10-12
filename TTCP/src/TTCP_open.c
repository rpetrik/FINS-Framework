//void tcp_Open(tcp_Socket *s, WORD lport, in_HwAddress ina, WORD port, procref datahandler)
void TTCP_open(tcp_Socket *s, WORD lport, in_HwAddress ina, WORD port,procref datahandler)
{
	//extern eth_HwAddress sed_ethBcastAddr;

	s->state = tcp_StateSYNSENT;
	s->timeout = tcp_LONGTIMEOUT;
	if ( lport == 0 ) lport = clock_ValueRough();
	s->myport = lport;
	if ( ! sar_MapIn2Eth(ina, &s->hisethaddr[0]) ) {
#ifdef DEBUG
		print(" : defaulting ethernet address to broadcast\r\n\r");
#endif
		Move(&sed_ethBcastAddr[0], &s->hisethaddr[0], sizeof(eth_HwAddress));
	}
	s->hisaddr = ina;
	s->hisport = port;
	s->seqnum = 0;
	s->dataSize = 0;
	s->flags = tcp_FlagSYN;
	s->unhappy = true;
	s->dataHandler = datahandler;
	s->next = tcp_allsocs;
	tcp_allsocs = s;
	tcp_Send(s);
}
#endif
