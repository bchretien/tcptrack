// after a connection has been closed for this many seconds,
// remove it
#define CLOSED_PURGE 2

// the display will be updated every DISPLAY_REFRESH nanoseconds.
//#define DISPLAY_REFRESH 10000
#define DISPLAY_REFRESH 1000000

// the packet queues will be processed every PKTBUF_PROC nanoseconds.
#define PKTBUF_PROC 10000

// this is the amount of time pcap_loop will wait for more packets before
// passing what it has to tcptrack. this is milliseconds. 
// This is passed to the third argument (to_ms) to pcap_open_live
#define POL_TO_MS 10

// the amount of time we will wait for a connection to finish opening after
// the initial syn has been sent before we dicard it
#define SYN_SYNACK_WAIT 30

// connections in the CLOSING state are removed after this timeout
#define FIN_FINACK_WAIT 60

// pcap snaplen. Should be as long as biggest link level header len + 
// vlan header len + IP header len + tcp header len.
#define SNAPLEN 100

// when fast mode is enabled, averages will be recalculated this freqently.
// if no fast mode, once per second.
//#define FASTMODE_INTERVAL 250000000 // one quarter of a second
#define FASTMODE_INTERVAL 100000000 // one tenth of a second

// stack sizes for the different threads
#define SS_PB  2048 // PacketBuffer
#define SS_S   4096 // Sniffer 2048 -> segfault on freebsd
#define SS_TCC 4096 // TCContainer
#define SS_TUI 5120 // TextUI. 4096 -> segfault on solaris
