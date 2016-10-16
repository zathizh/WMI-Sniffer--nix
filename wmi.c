#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <regex.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <time.h>

#include <unistd.h>

#define AUTH_PACK_H 74
#define BUF_SIZE 65536
#define TIME_BUF_SIZE 20
#define MTU 1536

char ifname[] = "ens33";	// ethernet interface name

char alrt[40];			// holds attempt message
char id[4];			// holds attempt id
char command[20];		// holds excuting commad
char time_buf[TIME_BUF_SIZE];	// holds timestamp

char *sour, *dest; 		// source and destination ip addresses as strings

struct ifreq    ethreq;		// ethernet 
struct sockaddr_in addrs;	// hold soruce and destination ip address

time_t curtime;			// time variables
struct tm *loctime;		// time variables

int sock_wmi;			// socket descriptor

FILE *log_fd; 			// log file descriptor

// reqular expression variables
regex_t obj_reg;
regex_t win32_reg; 
regex_t cim_reg;
// regular expression matched vaule stores
regmatch_t reg_match[2];

// for decrypted data
char *data;

const char *opnum_methods[] = {"","","",\
				"OpenNamespace",\
				"CancelAsyncCall",\
				"QueryObjectSink",\
				"GetObject",\
				"GetObjectAsync",\
				"PutClass",\
                                "PutClassAsync",\
				"DeleteClass",\
				"DeleteClassAsync",\
				"CreateClassEnum",\
				"CreateClassEnumAsync",\
				"PutInstance",\
                                "PutInstanceAsync",\
				"DeleteInstance",\
				"DeleteInstanceAsync",\
				"CreateInstanceEnum",\
				"CreateInstanceEnumAsync",\
                                "ExecQuery",\
				"ExecQueryAsync",\
				"ExecNotificationQuery",\
				"ExecNotificationQueryAsync",\
				"ExecMethod",\
				"ExecMethodAsync"};

struct dcerpc_hdr{
	u_int8_t version;
	u_int8_t version_minor;
	u_int8_t pack_type;
	u_int8_t pack_flag;

	u_int32_t data_rep;

	u_int16_t frag_len;
	u_int16_t auth_len;
	u_int32_t call_id;

	u_int32_t alloc_hint;
	u_int16_t context_id;
	u_int16_t op_num;

	unsigned char obj_uuid[16];
} __attribute__((packed));

struct dcerpc_trl{
	u_int8_t auth_type;
	u_int8_t auth_level;
	u_int8_t auth_pad_len;
	u_int8_t auth_rsvrd;
	u_int32_t auth_context_id;

	u_int32_t ntlmssp_ver_num;
	unsigned char ntlmssp_ver_body[12];
} __attribute__((packed));

struct dcerpc_auth{
	u_int8_t version;
        u_int8_t version_minor;
        u_int8_t pack_type;
        u_int8_t pack_flag;

        u_int32_t data_rep;

        u_int16_t frag_len;
        u_int16_t auth_len;
        u_int32_t call_id;

	u_int32_t unknown;

	u_int8_t auth_type;
        u_int8_t auth_level;
        u_int8_t auth_pad_len;
        u_int8_t auth_rsvrd;
        u_int32_t auth_context_id;

} __attribute__((packed));

struct ntlmssp{
	u_int64_t identifier;
	u_int32_t message_type;

	u_int16_t lan_man_res_length;
	u_int16_t lan_man_res_maxlen;
	u_int32_t lan_man_res_offset;

        u_int16_t ntlm_res_length;
        u_int16_t ntlm_res_maxlen;
        u_int32_t ntlm_res_offset;
	

        u_int16_t domain_name_length;
        u_int16_t domain_name_maxlen;
        u_int32_t domain_name_offset;

        u_int16_t user_name_length;
        u_int16_t user_name_maxlen;
        u_int32_t user_name_offset;

        u_int16_t host_name_length;
        u_int16_t host_name_maxlen;
        u_int32_t host_name_offset;

        u_int16_t session_key_length;
        u_int16_t session_key_maxlen;
        u_int32_t session_key_offset;

	u_int32_t negotiate_flags;

	__extension__ union
	{
		u_int64_t verson;

		struct {
			u_int8_t version_major_version;
			u_int8_t version_minor_version;
			u_int16_t version_build_number;
	
			unsigned char version_pad[3];
			u_int8_t  version_ntlm_cur_rev;
		};
	};

	unsigned char MIC[16];

} __attribute__((packed));

struct dcerpc_pack{
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
	struct dcerpc_hdr dcerpc_h;
} __attribute__((packed));

struct dcerpc_pack_auth{
        struct ethhdr eth;
        struct iphdr ip;
        struct tcphdr tcp;
        struct dcerpc_auth auth;
	struct ntlmssp ntlmssp_h;
} __attribute__((packed));


void my_cleanup( void )
{
        // turn off the interface's 'promiscuous' mode
        ethreq.ifr_flags &= ~IFF_PROMISC;
        if ( ioctl( sock_wmi, SIOCSIFFLAGS, &ethreq ) < 0 )
        {
                perror( "ioctl: set ifflags" );
                exit(1);
        }
	fclose(log_fd);
}

void my_handler( int signo )
{
        // This function executes when the user hits <CTRL-C>. 
        // It initiates program-termination, thus triggering
        // the 'cleanup' function we previously installed.
	printf("***Caught Int-Signal\n");
	printf("exiting wmi sniffer\n");
        exit(0);
}

void eth_print(char *buf){
        for (int i=0; i<ETH_ALEN; i++){
                if (i>0)
                        printf(":");
                if (buf[i] != 255)
                        printf("%02x", (unsigned char)buf[i]);
       }
	printf("\n");
}

// log authentication attempt details
void log_auth(unsigned char *buf){
	struct dcerpc_pack_auth *dce_auth = (struct dcerpc_pack_auth *)buf;
        fprintf(log_fd, "%s,", time_buf);			// timestamp
        fprintf(log_fd, "%s,", sour);				// source ip address
        fprintf(log_fd, "%s,", dest);				// destination ip address

        fprintf(log_fd, "%u,", ntohs(dce_auth->tcp.source));	// tcp source port
        fprintf(log_fd, "%u,", ntohs(dce_auth->tcp.dest));	// tcp destination port

        fprintf(log_fd, "%d,", dce_auth->auth.pack_type);	// dcerpc auth packet type
	fprintf(log_fd, "%d,", dce_auth->auth.auth_level);	// dcerpc auth packet authentication level
	fprintf(log_fd, "%s,", id);

        fprintf(log_fd, ",");
        fprintf(log_fd, ",");
        fprintf(log_fd, ",");

        fprintf(log_fd, "%s", data);				// raw data
        fprintf(log_fd, "\n");
}

// log execution details
void log_ex(unsigned char *buf){
	struct dcerpc_pack *dce_h = (struct dcerpc_pack *)buf;
	fprintf(log_fd, "%s,", time_buf);			// timestamp
	fprintf(log_fd, "%s,", sour);				// source ip address
	fprintf(log_fd, "%s,", dest);				// destination ip address
	
	fprintf(log_fd, "%u,", ntohs(dce_h->tcp.source));	// tcp source address
	fprintf(log_fd, "%u,", ntohs(dce_h->tcp.dest));		// tcp destination address

	fprintf(log_fd, ",");
	fprintf(log_fd, ",");
	fprintf(log_fd, ",");

	fprintf(log_fd, "%d,", dce_h->dcerpc_h.op_num);		// dcerpc packet op num
	fprintf(log_fd, "%s,", opnum_methods[dce_h->dcerpc_h.op_num]);	// method relevant to op num
	fprintf(log_fd, "%s,", command);			// executed command

	fprintf(log_fd, "%s", data);				// raw data
	fprintf(log_fd, "\n");
}

void alert_ex(unsigned char *buf, char *msg){
        memset(time_buf, 0, 20);
        curtime = time(NULL);
        loctime = localtime(&curtime);

        strftime(time_buf, TIME_BUF_SIZE, "%Y/%m/%d %H:%M:%S", loctime);

	struct iphdr *iph = (struct iphdr *)(buf+14);
        memset(&addrs, 0, sizeof(struct sockaddr_in));
        addrs.sin_addr.s_addr = iph->saddr;
	sour =  strdup(inet_ntoa(addrs.sin_addr));
        addrs.sin_addr.s_addr = iph->daddr;
	dest =  strdup(inet_ntoa(addrs.sin_addr));

	printf("%s : %s -> %s : %s", time_buf, sour, dest, msg);

}

void alert(unsigned char *buf, char *msg){
	memset(time_buf, 0, 20);
	curtime = time(NULL);
	loctime = localtime(&curtime);

	strftime(time_buf, TIME_BUF_SIZE, "%Y/%m/%d %H:%M:%S", loctime);

        struct iphdr *iph = (struct iphdr *)(buf+14);
        memset(&addrs, 0, sizeof(struct sockaddr_in));
        addrs.sin_addr.s_addr = iph->saddr;
        sour =  strdup(inet_ntoa(addrs.sin_addr));
        addrs.sin_addr.s_addr = iph->daddr;
        dest =  strdup(inet_ntoa(addrs.sin_addr));

        printf("%s : %s -> %s : %s\n", time_buf, sour, dest, msg);
}

void process_auth(unsigned char *buf, size_t nbytes, int spos, int epos){
	memset(data, 0, sizeof(BUF_SIZE));
        unsigned char   ch;
        int j=0;
        for (int i = spos; i < epos; i++){
                ch = buf[i];
                if (( ch < 0x20 )||( ch > 0x7E )){
                        continue;
                }
                data[j++] = ch;
        }
        data[j]='\0';
}

void process_data(unsigned char *buf, size_t nbytes, int spos, int epos){
	memset(data, 0, sizeof(BUF_SIZE));
	memset(command, 0, 20);
	unsigned char   ch;
	int j=0;
	for (int i = spos; i < epos; i++){
		ch = buf[i];
		if (( ch < 0x20 )||( ch > 0x7E )){
			continue;
		}
		data[j++] = ch;
	}
	data[j]='\0';

	if (regexec(&obj_reg, data, 1, reg_match, 0)){
		if (regexec(&win32_reg, data, 1, reg_match, 0)){
			if(regexec(&cim_reg, data, 1, reg_match, 0)){
				printf("%s\n", data);
			}
		}
	}
	if (reg_match[0].rm_so >= 0 && reg_match[0].rm_eo > 0){
		int j=0;
		for (int i = reg_match[0].rm_so; ; i++){
			if (((data[i] >  0x5A && data[i] < 0x61) || data[i] > 0x7A || data[i] < 0x41) && i > reg_match[0].rm_eo)
				break;
			command[j++]=data[i];
		}
		command [j] = '\0';
		printf("%s", command);
	}
	printf("\n");
	memset(reg_match, 0, 2);
}

void process(unsigned char *buf, ssize_t nbytes){
	strncpy(alrt,"Attempting to authenticate with id : ", 37);
	struct iphdr *iph = (struct iphdr *)(buf+14);

	if (iph->tot_len > 118){
		struct dcerpc_pack *dce_h = (struct dcerpc_pack *)buf;
		if (dce_h->dcerpc_h.version == 5){
			if(dce_h->dcerpc_h.pack_type == 16){
			struct dcerpc_pack_auth *dce_auth = (struct dcerpc_pack_auth *)buf;
				if (dce_auth->auth.auth_type == 10){
					switch(dce_auth->auth.auth_level){
						case 2:
							memset(id, 0, 4);
							alert(buf, "Attempting to connect");
							process_auth(buf, nbytes, sizeof(struct dcerpc_pack_auth), nbytes);
							log_auth(buf);
							break;
						case 4:
							memset(id, 0, 4);
                                                        snprintf(id, 4, "%d", dce_auth->auth.auth_context_id);
                                                        strncpy((alrt+37), id, 4);
                                                        alert(buf, alrt);
							process_auth(buf, nbytes, sizeof(struct dcerpc_pack_auth), nbytes);
							log_auth(buf);
							break;
					}
				}
                        }
			else{
				switch(dce_h->dcerpc_h.op_num){
					case 20:
					case 21:
					case 22:
					case 23:
					case 24:
					case 25:
						alert_ex(buf, "Executing  :  ");
						process_data(buf, nbytes, 118, (nbytes-24));
						log_ex(buf);
						break;
				}
			}
		}
	}
}

int main(int argc, char **argv){

	// create log file directory if not available
	struct stat st = {0};
	if (stat("/var/log/wmi/", &st) == -1) {
		mkdir("/var/log/wmi/", 0777);
	}

	// create log file or point the log file descriptor to log file
	if(!(log_fd = fopen("/var/log/wmi/wmi.log", "a+"))){
		perror("Error : Openning Log File ");
	}

	// checks if log file is empty
	fseek(log_fd, 0, SEEK_END);
	// if log file is empty write the login header
	if (ftell(log_fd) == 0){
		fprintf(log_fd, "Timestamp,Source IP,Dest IP,Source Port,Dest Port,DCERPC Auth Pack Type,\
				DCERPC Auth Level,Op Num,Method,Command,Raw Data\n");
	}

	// definition of regular expressions
	if (regcomp(&obj_reg, "%*object:Win32_%*", REG_EXTENDED)){
		perror("Error : Object:Win32_Regex ");
		exit(8);
	}
	if (regcomp(&win32_reg, "Win32_", REG_EXTENDED)){
		perror("Error : Win32_Regex ");
		exit(8);	
	}
	if (regcomp(&cim_reg, "cim_datafile", REG_EXTENDED)){
		perror("Error : CIM_DataFile_Regex ");
		exit(8);
	}
	
	ssize_t nbytes;
	// create socket for reception of ethernet packets
	if((sock_wmi = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("Error : Creating Socket ");
		exit(8);
	}

	// enable 'promiscuous mode' for the selected socket interface
	strncpy( ethreq.ifr_name, ifname, IFNAMSIZ );
	if ( ioctl( sock_wmi, SIOCGIFFLAGS, &ethreq ) < 0 )
	{
		perror("Error : IOCTL Get ifflags " );
		exit(1);
	}
	ethreq.ifr_flags |= IFF_PROMISC;  // enable 'promiscuous' mode
	if ( ioctl( sock_wmi, SIOCSIFFLAGS, &ethreq ) < 0 )
	{
		perror( "Error : IOCTL Set ifflags " );
		exit(1);
	}
        // make sure 'promiscuous mode' will get disabled upon termination
        atexit( my_cleanup );
        signal( SIGINT, my_handler );

	unsigned char *buf = (unsigned char *)malloc(BUF_SIZE);
	if (!buf){
		perror("Error : Allocating Memory for buffer ");
		exit(1);
	}

	data = (char *)malloc(BUF_SIZE);
	if (!data){
		perror("Error : Allocating Memory for data buffer ");
		exit(1);
	}

	memset(buf, 0, sizeof(BUF_SIZE));

	printf( "Monitoring WMI packets on interface \'%s\' \n", ifname );

	while(1){
		nbytes = recvfrom(sock_wmi, buf, BUF_SIZE, 0, 0, 0);	// capture all packet
		if (nbytes > 0){
			process(buf, nbytes);			// process captured packets finds WMI packets
		}
		memset(buf, 0, sizeof(BUF_SIZE));
	}

	free(buf);
	return 0;
}
