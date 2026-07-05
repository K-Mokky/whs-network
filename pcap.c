#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h> 
#include <netinet/in.h>


struct ethernet_header {
    char srcmac[6]; //출발지
    char dstmac[6];//목적지
    short mac_type;
};

struct ip_header {
    char iph_ihl:4; //헤더 길이 ( 필드 : 4비트, 단위 : 4바이트 )
    char iph_ver:4; //버전 ( 4비트 필드 ) 
    char iph_tos; //서비스 타입
    short iph_len; //전체 길이
    short iph_ident; //식별자
    short iph_flag:3; //플래그 ( 3비트 필드 )
    short iph_offset:13; //오프셋 ( 13비트 필드 )
    char iph_ttl;
    char iph_protocol;
    short int iph_chksum;
    struct in_addr srcip; //송신자
    struct in_addr dstip; //수신자
};

struct tcp_header {
    short srcport; //출발지 port
    short dstport; //목적지 port
    int tcp_seq; //순서
    int tcp_ack; //응답
    char tcp_offx2; //상위 4비트를 의미함과 동시에 헤더 길이를 의미.
    char tcp_flags; //플래그
    short tcp_win; //크기
    short tcp_sum; //체크섬
    short tcp_urp; //긴급포인터?
};

void packet_capture( char *args, const struct pcap_pkthdr *header, const char *packet ){

    struct ethernet_header *eth = ( struct ethernet_header * )packet;

    if( ntohs( eth -> mac_type ) != 0x0800 ) return;

    struct ip_header *ip = ( struct ip_header * )( packet + sizeof( struct ethernet_header ));

    if ( ip -> iph_protocol != IPPROTO_TCP ) return;

    int ip_header_len  = ip -> iph_ihl * 4;
    struct tcp_header *tcp = ( struct tcp_header * )(( u_char * )ip + ip_header_len );
    int tcp_header_len = ( tcp -> tcp_offx2 >> 4 ) * 4;

    printf("=============================================\n");
    printf("SRC MAC : %s\n", ether_ntoa(( struct ether_addr * )eth -> srcmac ));
    printf("DST MAC : %s\n", ether_ntoa(( struct ether_addr * )eth -> dstmac ));

    printf("SRC IP : %s\n", inet_ntoa( ip -> srcip ));
    printf("DST IP : %s\n", inet_ntoa( ip -> dstip ));

    printf("SRC Port : %d\n", ntohs( tcp->srcport ));
    printf("DST Port : %d\n", ntohs( tcp->dstport ));

    int total_len   = ntohs( ip -> iph_len );
    int payload_len = total_len - ip_header_len - tcp_header_len;
    const u_char *payload = ( u_char * )ip + ip_header_len + tcp_header_len;

    printf("Message (%d bytes):\n", payload_len);
    if ( payload_len > 0 ) {
        int show = payload_len > 200 ? 200 : payload_len;
        for ( int i = 0; i < show; i++ ) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("(no data)\n");
    }
    printf("\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";

    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if ( pcap_compile( handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN ) == -1 || pcap_setfilter( handle, &fp ) == -1 ){
        fprintf( stderr, "filter error: %s\n", pcap_geterr( handle ) );
        pcap_close( handle );
        return 1;
    }

    pcap_loop( handle, 0, packet_capture, NULL );

    pcap_close( handle );

    return 0;
}
