#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <map>
#include <string>
#include <arpa/inet.h>

// TLS Handshake Constants
#define TLS_CLIENT_HELLO 1

// TLS Handshake Header
struct tls_handshake_header {
	uint8_t msg_type;
	uint8_t length[3];  // 24-bit length
} __attribute__((packed));

// Key structure for segment reassembly
struct Key {
	uint32_t sip;
	uint16_t sport;
	uint32_t dip;
	uint16_t dport;

	bool operator<(const Key& r) const {
		if (sip != r.sip) return sip < r.sip;
		if (sport != r.sport) return sport < r.sport;
		if (dip != r.dip) return dip < r.dip;
		return dport < r.dport;
	}

	bool operator>(const Key& r) const {
		return r < *this;
	}

	bool operator==(const Key& r) const {
		return sip == r.sip && sport == r.sport && 
			dip == r.dip && dport == r.dport;
	}
};

// Structure to hold segment information
struct SegmentInfo {
	std::string data;
	uint32_t expected_length;
	bool has_header;

	SegmentInfo() : expected_length(0), has_header(false) {}
};

std::map<Key, SegmentInfo> segments;

void usage() {
	printf("syntax : tls-block <interface> <server_name>\n");
	printf("sample : tls-block wlan0 naver.com\n");
}

// Extract 24-bit length from TLS handshake header
uint32_t get_handshake_length(const uint8_t* length_bytes) {
	return (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2];
}

// Parse SNI from Client Hello data
std::string extract_sni_from_client_hello(const uint8_t* client_hello_data, uint32_t data_len) {
	if (data_len < 38) return "";  // Minimum Client Hello size

	uint32_t offset = 2;  // Skip version (2 bytes)
	offset += 32;         // Skip random (32 bytes)

	// Skip session ID
	if (offset >= data_len) return "";
	uint8_t session_id_len = client_hello_data[offset];
	offset += 1 + session_id_len;

	// Skip cipher suites
	if (offset + 2 >= data_len) return "";
	uint16_t cipher_suites_len = ntohs(*(uint16_t*)(client_hello_data + offset));
	offset += 2 + cipher_suites_len;

	// Skip compression methods
	if (offset >= data_len) return "";
	uint8_t compression_len = client_hello_data[offset];
	offset += 1 + compression_len;

	// Check if extensions are present
	if (offset + 2 >= data_len) return "";
	uint16_t extensions_len = ntohs(*(uint16_t*)(client_hello_data + offset));
	offset += 2;

	// Parse extensions
	uint32_t extensions_end = offset + extensions_len;
	while (offset + 4 <= extensions_end && offset + 4 <= data_len) {
		uint16_t ext_type = ntohs(*(uint16_t*)(client_hello_data + offset));
		uint16_t ext_len = ntohs(*(uint16_t*)(client_hello_data + offset + 2));
		offset += 4;

		if (offset + ext_len > data_len) break;

		// SNI extension type is 0x0000
		if (ext_type == 0x0000 && ext_len >= 5) {
			if (offset + 5 <= data_len) {
				uint16_t name_list_len = ntohs(*(uint16_t*)(client_hello_data + offset));
				uint8_t name_type = client_hello_data[offset + 2];
				uint16_t hostname_len = ntohs(*(uint16_t*)(client_hello_data + offset + 3));

				if (name_type == 0 && offset + 5 + hostname_len <= data_len) {
					return std::string((char*)(client_hello_data + offset + 5), hostname_len);
				}
			}
		}

		offset += ext_len;
	}

	return "";
}

// Parse TLS handshake data
std::string parse_tls_handshake(const uint8_t* handshake_data, uint32_t data_len) {
	if (data_len < sizeof(tls_handshake_header)) return "";

	const tls_handshake_header* hs_hdr = (const tls_handshake_header*)handshake_data;

	// Check if it's a Client Hello
	if (hs_hdr->msg_type != TLS_CLIENT_HELLO) return "";

	uint32_t handshake_len = get_handshake_length(hs_hdr->length);
	if (data_len < sizeof(tls_handshake_header) + handshake_len) {
		// Incomplete handshake, need more data
		return "";
	}

	const uint8_t* client_hello_data = handshake_data + sizeof(tls_handshake_header);

	return extract_sni_from_client_hello(client_hello_data, handshake_len);
}

// Handle handshake segment reassembly
std::string handle_handshake_reassembly(const Key& key, const uint8_t* handshake_data, uint32_t data_len) {
	SegmentInfo& segment = segments[key];

	// If this is the first segment and contains handshake header
	if (!segment.has_header && data_len >= 4) {
		const tls_handshake_header* hs_hdr = (const tls_handshake_header*)handshake_data;
		if (hs_hdr->msg_type == TLS_CLIENT_HELLO) {
			segment.expected_length = get_handshake_length(hs_hdr->length) + 4;  // +4 for header
			segment.has_header = true;
			printf("Client Hello detected, expected length: %u bytes\n", segment.expected_length);
		}
	}

	// Accumulate data
	segment.data += std::string((char*)handshake_data, data_len);

	//printf("Accumulated %u bytes, total: %u bytes\n", data_len, (uint32_t)segment.data.length());

	// Check if we have enough data
	if (segment.has_header && segment.data.length() >= segment.expected_length) {
		std::string sni = parse_tls_handshake((const uint8_t*)segment.data.c_str(), segment.data.length());

		if (!sni.empty()) {
			// Clear the segment after successful parsing
			segments.erase(key);
			return sni;
		}
	}

	// Try to parse even if we don't have complete data (in case our length calculation is wrong)
	std::string sni = parse_tls_handshake((const uint8_t*)segment.data.c_str(), segment.data.length());
	if (!sni.empty()) {
		segments.erase(key);
		return sni;
	}

	return "";
}

// checksum calculate
unsigned short checksum(unsigned short *buffer, int size){
	unsigned long cksum=0;
	while(size >1) {
		cksum+=*buffer++;
		size -=sizeof(unsigned short);
	}
	if(size) {
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (unsigned short)(~cksum);
}

// send packet to server (forward)
void send_forward_packet(pcap_t* pcap, const u_char* org_packet, struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len, uint8_t* my_mac) {
	// length of each section
	int ethdr_len, iphdr_len, tcphdr_len, packet_len;
	ethdr_len = LIBNET_ETH_H;
	iphdr_len = (iphdr -> ip_hl) * 4;
	tcphdr_len = (tcphdr -> th_off) * 4;
	packet_len = LIBNET_ETH_H + iphdr_len + tcphdr_len;

	// packet to send
	u_char packet[packet_len];
	memset(packet, 0, packet_len);
	memcpy(packet, org_packet, packet_len);

	// ethernet header
	struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
	// change source mac
	memcpy(ethdr->ether_shost, my_mac, ETHER_ADDR_LEN);

	// ipv4 header
	struct libnet_ipv4_hdr* new_iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
	new_iphdr->ip_len = htons(iphdr_len + tcphdr_len);
	new_iphdr->ip_sum = 0;
	new_iphdr->ip_sum = checksum((unsigned short*)new_iphdr, iphdr_len);

	// tcp rst packet
	struct libnet_tcp_hdr* new_tcphdr = (struct libnet_tcp_hdr*)(packet + ethdr_len + iphdr_len);
	// change seq number, flag
	new_tcphdr->th_seq = htonl(ntohl(tcphdr->th_seq) + data_len);
	new_tcphdr->th_flags = TH_RST | TH_ACK;
	new_tcphdr->th_sum = 0;

	// calculate tcp checksum using pseudo header
	u_char pseudo_hdr[12 + tcphdr_len];
	memcpy(pseudo_hdr, &new_iphdr->ip_src.s_addr, 4);
	memcpy(pseudo_hdr + 4, &new_iphdr->ip_dst.s_addr, 4);
	pseudo_hdr[8] = 0;
	pseudo_hdr[9] = IPPROTO_TCP;
	unsigned short tcp_len = htons(tcphdr_len);
	memcpy(pseudo_hdr + 10, &tcp_len, 2);
	memcpy(pseudo_hdr + 12, new_tcphdr, tcphdr_len);

	new_tcphdr->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcphdr_len);

	if (pcap_sendpacket(pcap, (const u_char*)packet, packet_len)) {
		fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
	}
}

// send packet to client (backward)
void send_backward_packet(struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, uint32_t data_len) {
	// Fin은 직접 패킷 정보 입력해줘야 무한로딩 안 걸림. 정확한 이유는 모르겠지만 패킷의 어떤 정보가 소켓으로 전송하는 것과 안 맞는듯하다.
	// length of each section
	int iphdr_len, tcphdr_len, packet_len;
	iphdr_len = (iphdr -> ip_hl) * 4;
	tcphdr_len = (tcphdr -> th_off) * 4;
	packet_len = iphdr_len + tcphdr_len;

	// packet to send
	u_char packet[packet_len];
	memset(packet, 0, packet_len);

	// exchange server <-> client
	struct libnet_ipv4_hdr* new_iphdr = (struct libnet_ipv4_hdr*)packet;
	// swap source and destination
	new_iphdr->ip_src = iphdr->ip_dst;
	new_iphdr->ip_dst = iphdr->ip_src;
	new_iphdr->ip_hl = iphdr_len / 4;
	new_iphdr->ip_v = 4;
	new_iphdr->ip_len = htons(packet_len);
	new_iphdr->ip_ttl = 128;
	new_iphdr->ip_p = IPPROTO_TCP;
	new_iphdr->ip_sum = 0;
	new_iphdr->ip_sum = checksum((unsigned short*)new_iphdr, iphdr_len);

	// exchange server <-> client / tcp fin packet
	struct libnet_tcp_hdr* new_tcphdr = (struct libnet_tcp_hdr*)(packet + iphdr_len);
	// swap source and destination
	new_tcphdr->th_sport = tcphdr->th_dport;
	new_tcphdr->th_dport = tcphdr->th_sport;
	new_tcphdr->th_seq = tcphdr->th_ack;
	new_tcphdr->th_ack = htonl(ntohl(tcphdr->th_seq) + data_len);
	new_tcphdr->th_flags = TH_RST | TH_ACK;
	new_tcphdr->th_off = tcphdr_len / 4;
	// tcp header window size = 65535
	new_tcphdr->th_win = htons(60000);
	new_tcphdr->th_sum = 0;

	// calculate tcp checksum using pseudo header
	u_char pseudo_hdr[12 + tcphdr_len];
	memcpy(pseudo_hdr, &new_iphdr->ip_src.s_addr, 4);
	memcpy(pseudo_hdr + 4, &new_iphdr->ip_dst.s_addr, 4);
	pseudo_hdr[8] = 0;
	pseudo_hdr[9] = IPPROTO_TCP;
	unsigned short tcp_len = htons(tcphdr_len);
	memcpy(pseudo_hdr + 10, &tcp_len, 2);
	memcpy(pseudo_hdr + 12, new_tcphdr, tcphdr_len);

	new_tcphdr->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcphdr_len);

	// send through raw socket
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	int on = 1;
	// IP_HDRINCL: user provided ip header
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = new_tcphdr->th_dport;
	address.sin_addr.s_addr = new_iphdr->ip_dst.s_addr;

	if (sendto(sd, packet, packet_len, 0, (struct sockaddr *)&address, sizeof(address)) < 0) {
		fprintf(stderr, "Failed to send backward packet\n");
	}
	close(sd);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return 0;
	}

	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	uint8_t mac[6];

	libnet_t* ln = libnet_init(LIBNET_LINK, dev, NULL);
	if (ln == NULL) {
		fprintf(stderr, "libnet_init failed\n");
		libnet_destroy(ln);
		return -1;
	}

	struct libnet_ether_addr* my_mac = libnet_get_hwaddr(ln);
	if (my_mac == NULL) {
		fprintf(stderr, "libnet_get_hwaddr failed\n");
		libnet_destroy(ln);
		return -1;
	}

	memcpy(mac, my_mac->ether_addr_octet, 6);
	libnet_destroy(ln);

	printf("TLS Handshake Analysis started for server: %s\n", pattern);
	struct pcap_pkthdr* header;
	const u_char* packet;

	while (1) {
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// Parse packet headers
		if (header->len < 54) continue;

		uint32_t ethdr_len, iphdr_len, tcphdr_len;

		struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(ethdr->ether_type) != ETHERTYPE_IP) continue;
		ethdr_len = LIBNET_ETH_H;

		struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
		if (iphdr->ip_p != IPPROTO_TCP) continue;
		iphdr_len = (iphdr->ip_hl) * 4;

		struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)(packet + ethdr_len + iphdr_len);
		// Check if it's HTTPS traffic (port 443)
		if (ntohs(tcphdr->th_dport) != 443 && ntohs(tcphdr->th_sport) != 443) continue;
		tcphdr_len = (tcphdr->th_off) * 4;

		const uint8_t* data = packet + LIBNET_ETH_H + iphdr_len + tcphdr_len;
		uint32_t data_len = ntohs(iphdr->ip_len) - iphdr_len - tcphdr_len;

		if (data_len == 0) continue;

		// Create key for this connection
		Key key;
		key.sip = iphdr->ip_src.s_addr;
		key.sport = tcphdr->th_sport;
		key.dip = iphdr->ip_dst.s_addr;
		key.dport = tcphdr->th_dport;

		std::string sni;

		// Check if this looks like TLS handshake data
		if (data_len > 5 && data[0] == 22) {  // TLS Handshake record type
			const uint8_t* handshake_data = data + 5;  // Skip TLS record header
			uint32_t handshake_len = data_len - 5;

			sni = handle_handshake_reassembly(key, handshake_data, handshake_len);
		} else {
			// Handle cases where TLS record header might be in previous packet
			// Just treat all data as potential handshake data
			sni = handle_handshake_reassembly(key, data, data_len);
		}

		if (!sni.empty()) {
			const char* server_name = sni.c_str();
			printf("Found SNI: %s\n", server_name);

			if (memmem(server_name, strlen(server_name), pattern, strlen(pattern)) != NULL) {
				printf("*** TARGET SERVER DETECTED: %s ***\n", sni.c_str());

				char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &iphdr->ip_dst, dst_ip, INET_ADDRSTRLEN);

				printf("Connection: %s:%d -> %s:%d\n", 
						src_ip, ntohs(tcphdr->th_sport),
						dst_ip, ntohs(tcphdr->th_dport));


				// Here you would send blocking packets in a real implementation
				printf("Would block this connection\n");
				send_backward_packet(iphdr, tcphdr, data_len);
				send_forward_packet(pcap, packet, iphdr, tcphdr, data_len, mac);
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
