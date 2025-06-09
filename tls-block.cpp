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

// Enhanced structure to hold segment information with fragmentation tracking
struct SegmentInfo {
	std::string data;
	uint32_t expected_length;
	bool has_header;
	uint32_t fragment_count;        // Number of fragments received
	uint32_t first_fragment_size;   // Size of first fragment
	bool is_fragmented;             // Flag to indicate if this handshake is fragmented

	SegmentInfo() : expected_length(0), has_header(false), fragment_count(0), first_fragment_size(0), is_fragmented(false) {}
};

std::map<Key, SegmentInfo> segments;

// Statistics
uint32_t total_handshakes = 0;
uint32_t fragmented_handshakes = 0;

void usage() {
	printf("syntax : tls-block <interface> <server_name>\n");
	printf("sample : tls-block wlan0 naver.com\n");
}

// Extract 24-bit length from TLS handshake header
// nthos: 2bytes, ntohs: 4bytes
// 3바이트는 사용 불가. 그래서 함수 따로 만듦듦
uint32_t get_handshake_length(const uint8_t* length_bytes) {
	return (length_bytes[0] << 16) | (length_bytes[1] << 8) | length_bytes[2];
}

// erase_function
// Helper function to print connection info
void print_connection_info(const Key& key) {
	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &key.sip, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &key.dip, dst_ip, INET_ADDRSTRLEN);
	printf("    Connection: %s:%d -> %s:%d", 
		   src_ip, ntohs(key.sport), dst_ip, ntohs(key.dport));
}

// Detect TLS record fragmentation
bool detect_tls_record_fragmentation(const uint8_t* data, uint32_t data_len) {
	if (data_len > 5 && data[0] == 22) {  // TLS Handshake record
		uint16_t tls_record_length = ntohs(*(uint16_t*)(data + 3));
		uint32_t actual_payload = data_len - 5;  // Subtract TLS record header
		
        // tls header에 적혀있는 2byte length보다 실제 측정된 length가 더 작다면 패킷이 분리됐다는 뜻. 나머지 찾아야 됨.
		if (actual_payload < tls_record_length) {
			printf("🔍 TLS RECORD FRAGMENTATION DETECTED!\n");
			printf("    TLS Record Header indicates: %u bytes\n", tls_record_length);
			printf("    Actually received payload: %u bytes\n", actual_payload);
			printf("    Missing: %u bytes\n", tls_record_length - actual_payload);
			return true;
		}
	}
	return false;
}

// Detect handshake fragmentation based on expected length
bool detect_handshake_fragmentation(const uint8_t* handshake_data, uint32_t data_len) {
	if (data_len >= 4) {
		const tls_handshake_header* hs_hdr = (const tls_handshake_header*)handshake_data;
		if (hs_hdr->msg_type == TLS_CLIENT_HELLO) {
			uint32_t expected_handshake_len = get_handshake_length(hs_hdr->length);
			uint32_t actual_handshake_len = data_len - 4;  // Subtract handshake header (handshake type (1byte) + length (3byte))
			
            // handshake protocol header에 적혀있는 length보다 실제 length가 더 작다면 패킷이 분리됐다는 뜻. 나머지 찾아야 됨.
			if (actual_handshake_len < expected_handshake_len) {
				printf("🔍 HANDSHAKE FRAGMENTATION DETECTED!\n");
				printf("    Handshake Header indicates: %u bytes\n", expected_handshake_len);
				printf("    Actually received payload: %u bytes\n", actual_handshake_len);
				printf("    Missing: %u bytes\n", expected_handshake_len - actual_handshake_len);
				return true;
			}
		}
	}
	return false;
}

// Parse SNI from Client Hello data
std::string extract_sni_from_client_hello(const uint8_t* client_hello_data, uint32_t data_len) {
	if (data_len < 38) return "";  // protocol ver(2byte) + random (32byte) + session id length (1byte) + cipher suites length (2byte) + compression length (1byte)

	uint32_t offset = 2;  // Skip version (2 bytes)
	offset += 32;         // Skip random (32 bytes)

	// Skip session ID
	if (offset >= data_len) return "";
	uint8_t session_id_len = client_hello_data[offset];
	offset += 1 + session_id_len;

	// Skip cipher suites
	if (offset >= data_len) return "";
	uint16_t cipher_suites_len = ntohs(*(uint16_t*)(client_hello_data + offset));
	offset += 2 + cipher_suites_len;

	// Skip compression methods
	if (offset >= data_len) return "";
	uint8_t compression_len = client_hello_data[offset];
	offset += 1 + compression_len;

	// Check if extensions are present
	if (offset >= data_len) return "";
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
		printf("⚠️  INCOMPLETE HANDSHAKE: Need %u more bytes\n", 
			   (uint32_t)(sizeof(tls_handshake_header) + handshake_len - data_len));
		return "";
	}

	const uint8_t* client_hello_data = handshake_data + sizeof(tls_handshake_header);

	return extract_sni_from_client_hello(client_hello_data, handshake_len);
}

// Enhanced handshake segment reassembly with detailed logging
std::string handle_handshake_reassembly(const Key& key, const uint8_t* handshake_data, uint32_t data_len, bool has_tls_header) {
	SegmentInfo& segment = segments[key];
	bool is_new_connection = (segment.fragment_count == 0);

	// Increment fragment counter
	segment.fragment_count++;

	printf("\n📦 PACKET FRAGMENT #%u RECEIVED:\n", segment.fragment_count);
	print_connection_info(key);
	printf("\n    Fragment size: %u bytes\n", data_len);
	printf("    Has TLS record header: %s\n", has_tls_header ? "Yes" : "No");

	// If this is the first segment and contains handshake header
	if (!segment.has_header && data_len >= 4) {
		const tls_handshake_header* hs_hdr = (const tls_handshake_header*)handshake_data;
		if (hs_hdr->msg_type == TLS_CLIENT_HELLO) {
			segment.expected_length = get_handshake_length(hs_hdr->length) + 4;  // +4 for header
			segment.has_header = true;
			segment.first_fragment_size = data_len;
			
			printf("✅ CLIENT HELLO DETECTED:\n");
			printf("    Expected total length: %u bytes\n", segment.expected_length);
			printf("    First fragment size: %u bytes\n", data_len);
			
			// Check if this will be fragmented
			if (data_len < segment.expected_length) {
				segment.is_fragmented = true;
				printf("🔍 FRAGMENTATION DETECTED: Need %u more bytes\n", 
					   segment.expected_length - data_len);
			} else {
				printf("✅ COMPLETE IN SINGLE PACKET\n");
			}
		}
	}

	// Accumulate data
	uint32_t old_size = segment.data.length();
	segment.data += std::string((char*)handshake_data, data_len);
	uint32_t new_size = segment.data.length();

	printf("📊 REASSEMBLY STATUS:\n");
	printf("    Previous total: %u bytes\n", old_size);
	printf("    Added this packet: %u bytes\n", data_len);
	printf("    New total: %u bytes\n", new_size);

	if (segment.has_header) {
		printf("    Progress: %u/%u bytes (%.1f%%)\n", 
			   new_size, segment.expected_length,
			   (float)new_size / segment.expected_length * 100.0);
	}

	// Check if we have enough data
	if (segment.has_header && segment.data.length() >= segment.expected_length) {
		printf("✅ REASSEMBLY COMPLETE!\n");
		
		if (segment.is_fragmented) {
			printf("🎯 FRAGMENTED HANDSHAKE SUCCESSFULLY REASSEMBLED:\n");
			printf("    Total fragments: %u\n", segment.fragment_count);
			printf("    First fragment: %u bytes\n", segment.first_fragment_size);
			printf("    Total size: %u bytes\n", new_size);
			fragmented_handshakes++;
		}
		
		total_handshakes++;
		
		std::string sni = parse_tls_handshake((const uint8_t*)segment.data.c_str(), segment.data.length());

		if (!sni.empty()) {
			printf("🌐 SNI EXTRACTED: %s\n", sni.c_str());
			// Clear the segment after successful parsing
			segments.erase(key);
			return sni;
		} else {
			printf("❌ FAILED TO EXTRACT SNI\n");
		}
	} else if (segment.has_header) {
		printf("⏳ WAITING FOR MORE FRAGMENTS...\n");
		printf("    Still need: %u bytes\n", segment.expected_length - new_size);
	}

	// Try to parse even if we don't have complete data (fallback)
	std::string sni = parse_tls_handshake((const uint8_t*)segment.data.c_str(), segment.data.length());
	if (!sni.empty()) {
		printf("✅ EARLY SNI EXTRACTION SUCCESSFUL: %s\n", sni.c_str());
		if (segment.is_fragmented) {
			fragmented_handshakes++;
		}
		total_handshakes++;
		segments.erase(key);
		return sni;
	}

	return "";
}

// erase_function
// Print fragmentation statistics
void print_fragmentation_stats() {
	printf("\n📈 FRAGMENTATION STATISTICS:\n");
	printf("    Total handshakes processed: %u\n", total_handshakes);
	printf("    Fragmented handshakes: %u\n", fragmented_handshakes);
	printf("    Fragmentation rate: %.1f%%\n", 
		   total_handshakes > 0 ? (float)fragmented_handshakes / total_handshakes * 100.0 : 0.0);
	printf("    Active reassembly buffers: %zu\n", segments.size());
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
    // 기존 패킷 복사 후 내부 변수만 변경 시 계속 에러 발생. 그냥 패킷 새로 구성함.
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

	// exchange server <-> client / tcp rst packet
	struct libnet_tcp_hdr* new_tcphdr = (struct libnet_tcp_hdr*)(packet + iphdr_len);
	// swap source and destination
	new_tcphdr->th_sport = tcphdr->th_dport;
	new_tcphdr->th_dport = tcphdr->th_sport;
	new_tcphdr->th_seq = tcphdr->th_ack;
	new_tcphdr->th_ack = htonl(ntohl(tcphdr->th_seq) + data_len);
    // 이번에는 rst 패킷 전송. 따로 payload 없음
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

	printf("🔍 TLS Handshake Analysis with Fragmentation Detection\n");
	printf("Target server pattern: %s\n", pattern);
	printf("Listening on interface: %s\n\n", dev);
	
	struct pcap_pkthdr* header;
	const u_char* packet;
	uint32_t packet_count = 0;

	while (1) {
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		packet_count++;

        /*
		// Parse packet headers
		if (header->len < 54) continue;
        */

		uint32_t ethdr_len, iphdr_len, tcphdr_len;

		struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(ethdr->ether_type) != ETHERTYPE_IP) continue;
		ethdr_len = LIBNET_ETH_H;

		struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
		if (iphdr->ip_p != IPPROTO_TCP) continue;
		iphdr_len = (iphdr->ip_hl) * 4;

		struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)(packet + ethdr_len + iphdr_len);
		// Check if it's HTTPS traffic (port 443)
		// if (ntohs(tcphdr->th_dport) != 443 && ntohs(tcphdr->th_sport) != 443) continue;
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

		printf("\n============================================================\n");
		printf("📋 PROCESSING PACKET #%u (%u bytes payload)\n", packet_count, data_len);

		std::string sni;
		bool has_tls_header = false;

		// Check if this looks like TLS handshake data
		if (data_len > 5 && data[0] == 22) {  // TLS Handshake record type
			has_tls_header = true;
			printf("✅ TLS RECORD HEADER DETECTED (Type: Handshake)\n");
			
			// Detect TLS record level fragmentation
			detect_tls_record_fragmentation(data, data_len);
			
			const uint8_t* handshake_data = data + 5;  // Skip TLS record header
			uint32_t handshake_len = data_len - 5;

			// Detect handshake level fragmentation
			detect_handshake_fragmentation(handshake_data, handshake_len);

			sni = handle_handshake_reassembly(key, handshake_data, handshake_len, has_tls_header);
		} else {
			printf("📦 CONTINUATION PACKET (No TLS record header)\n");
			// Handle cases where TLS record header might be in previous packet
			// Just treat all data as potential handshake data
			sni = handle_handshake_reassembly(key, data, data_len, has_tls_header);
		}

		if (!sni.empty()) {
			const char* server_name = sni.c_str();
			printf("\n🎯 SNI FOUND: %s\n", server_name);

			if (memmem(server_name, strlen(server_name), pattern, strlen(pattern)) != NULL) {
				printf("\n🚨 *** TARGET SERVER DETECTED: %s ***\n", sni.c_str());

				char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &iphdr->ip_dst, dst_ip, INET_ADDRSTRLEN);

				printf("Connection: %s:%d -> %s:%d\n", 
						src_ip, ntohs(tcphdr->th_sport),
						dst_ip, ntohs(tcphdr->th_dport));

				printf("🔨 BLOCKING CONNECTION...\n");
				send_backward_packet(iphdr, tcphdr, data_len);
				send_forward_packet(pcap, packet, iphdr, tcphdr, data_len, mac);
				printf("✅ CONNECTION BLOCKED\n");

				// Print stats after each block
				print_fragmentation_stats();
			}
		}

		// Print periodic stats every 50 packets
		if (packet_count % 50 == 0) {
			print_fragmentation_stats();
		}
	}

	pcap_close(pcap);
	printf("\n🏁 FINAL STATISTICS:\n");
	print_fragmentation_stats();
	return 0;
}
