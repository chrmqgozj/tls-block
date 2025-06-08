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

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return 0;
	}

	char* dev = argv[1];
	char* target_server = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	printf("TLS Handshake Analysis started for server: %s\n", target_server);

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

		struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(ethdr->ether_type) != ETHERTYPE_IP) continue;

		struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
		if (iphdr->ip_p != IPPROTO_TCP) continue;

		uint32_t iphdr_len = (iphdr->ip_hl) * 4;
		struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)((uint8_t*)iphdr + iphdr_len);
		uint32_t tcphdr_len = (tcphdr->th_off) * 4;

		// Check if it's HTTPS traffic (port 443)
		if (ntohs(tcphdr->th_dport) != 443 && ntohs(tcphdr->th_sport) != 443) continue;

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
			
			if (memmem(server_name, strlen(server_name), target_server, strlen(target_server)) != NULL) {
				printf("*** TARGET SERVER DETECTED: %s ***\n", sni.c_str());

				char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &iphdr->ip_dst, dst_ip, INET_ADDRSTRLEN);

				printf("Connection: %s:%d -> %s:%d\n", 
						src_ip, ntohs(tcphdr->th_sport),
						dst_ip, ntohs(tcphdr->th_dport));
				
				
				// Here you would send blocking packets in a real implementation
				printf("Would block this connection\n");
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
