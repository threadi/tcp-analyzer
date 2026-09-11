<?php
/**
 * File to hold a test double exposing the internals of Socket_Method.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Traceroute\Socket_Method;

/**
 * Exposes the protected packet building and parsing of Socket_Method.
 *
 * Sending and receiving needs CAP_NET_RAW and a real network peer, so the
 * parts that can be tested deterministically - header layout, checksum and
 * reply matching - are reached through this double instead.
 */
final class Socket_Method_Double extends Socket_Method {

	/**
	 * Build one probe packet.
	 *
	 * @param string $destination_ip The target IPv4 address.
	 * @param int    $ttl            TTL to set in the IP header.
	 * @param int    $identifier     ICMP identifier.
	 * @param int    $sequence       ICMP sequence.
	 * @return string
	 */
	public function expose_build_probe( string $destination_ip, int $ttl, int $identifier, int $sequence ): string {
		return $this->build_probe( $destination_ip, $ttl, $identifier, $sequence );
	}

	/**
	 * Build an ICMP echo request.
	 *
	 * @param int $identifier ICMP identifier.
	 * @param int $sequence   ICMP sequence.
	 * @return string
	 */
	public function expose_build_echo_request( int $identifier, int $sequence ): string {
		return $this->build_echo_request( $identifier, $sequence );
	}

	/**
	 * Check whether a packet is a reply to one of our probes.
	 *
	 * @param string $packet     The raw packet, starting with its IP header.
	 * @param int    $identifier The identifier to match.
	 * @param int    $sequence   The sequence to match.
	 * @return array{final:bool}|null
	 */
	public function expose_parse_reply( string $packet, int $identifier, int $sequence ): ?array {
		return $this->parse_reply( $packet, $identifier, $sequence );
	}

	/**
	 * Compute the internet checksum of a block of data.
	 *
	 * @param string $data The data to sum over.
	 * @return int
	 */
	public function expose_checksum( string $data ): int {
		return $this->checksum( $data );
	}
}
