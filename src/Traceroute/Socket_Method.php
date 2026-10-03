<?php
/**
 * File to handle the traceroute method using raw sockets.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Traceroute;

use Socket;

/**
 * Traces a route without any external binary, using raw sockets.
 *
 * Sends ICMP echo requests with an increasing TTL and reads the "time
 * exceeded" replies the routers on the path send back. PHP cannot set the
 * IPv4 TTL on a normal socket - ext-sockets exports neither IP_TTL nor
 * IP_HDRINCL - so the IP header is built by hand and sent through an
 * IPPROTO_RAW socket, which implies IP_HDRINCL on Linux.
 *
 * Both sending and receiving therefore need raw sockets, i.e. CAP_NET_RAW
 * or root. On shared hosting this is never granted, and check_availability()
 * reports "raw_socket_denied" accordingly. IPv4 only.
 */
class Socket_Method implements Method_Interface {

	/**
	 * Protocol number of ICMP.
	 *
	 * @var int
	 */
	private const PROTOCOL_ICMP = 1;

	/**
	 * Protocol number of IPPROTO_RAW. A socket opened with it implies
	 * IP_HDRINCL, i.e. the IP header is taken from the payload.
	 *
	 * @var int
	 */
	private const PROTOCOL_RAW = 255;

	/**
	 * ICMP message types this method cares about.
	 *
	 * @var int
	 */
	private const ICMP_ECHO_REPLY    = 0;
	private const ICMP_UNREACHABLE   = 3;
	private const ICMP_ECHO_REQUEST  = 8;
	private const ICMP_TIME_EXCEEDED = 11;

	/**
	 * Payload sent with every probe. Fixed, so replies stay comparable.
	 *
	 * @var string
	 */
	private const PAYLOAD = 'tcp-analyzer-probe-0000000000000';

	/**
	 * Number of probes sent per hop.
	 *
	 * @var int
	 */
	private int $probes;

	/**
	 * Maximum runtime of a trace in seconds.
	 *
	 * @var int
	 */
	private int $max_duration;

	/**
	 * Constructor.
	 *
	 * @param int $probes       Number of probes per hop, defaults to 3 like the traceroute binary.
	 * @param int $max_duration Maximum runtime of a trace in seconds. Every probe that gets no reply
	 *                          costs the full wait time, so a trace through silent hops could
	 *                          otherwise run for minutes. Once the time is up, the hops found so
	 *                          far are returned.
	 */
	public function __construct( int $probes = 3, int $max_duration = 30 ) {
		$this->probes       = max( 1, $probes );
		$this->max_duration = max( 1, $max_duration );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'socket';
	}

	/**
	 * {@inheritDoc}
	 */
	public function check_availability(): ?string {
		if ( ! extension_loaded( 'sockets' ) || ! function_exists( 'socket_create' ) ) {
			return 'sockets_unavailable';
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- a denied raw socket is the expected case, not an error to surface.
		$probe_socket = @socket_create( AF_INET, SOCK_RAW, self::PROTOCOL_ICMP );

		if ( ! $probe_socket instanceof Socket ) {
			return 'raw_socket_denied';
		}

		socket_close( $probe_socket );

		return null;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $host The target host.
	 * @param int    $max_hops Maximum number of hops to probe.
	 * @param int    $wait Per-hop wait time in seconds.
	 * @return array<int,array{hop:int,ip:?string,times_ms:float[]}>
	 */
	public function trace( string $host, int $max_hops, int $wait ): array {
		$destination_ip = filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? $host : gethostbyname( $host );

		if ( ! filter_var( $destination_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return array();
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- availability is reported via check_availability(), not via warnings.
		$send_socket = @socket_create( AF_INET, SOCK_RAW, self::PROTOCOL_RAW );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- see above.
		$receive_socket = @socket_create( AF_INET, SOCK_RAW, self::PROTOCOL_ICMP );

		if ( ! $send_socket instanceof Socket || ! $receive_socket instanceof Socket ) {
			if ( $send_socket instanceof Socket ) {
				socket_close( $send_socket );
			}

			if ( $receive_socket instanceof Socket ) {
				socket_close( $receive_socket );
			}

			return array();
		}

		socket_set_nonblock( $receive_socket );

		$identifier = getmypid() & 0xFFFF;
		$hops       = array();
		$deadline   = microtime( true ) + $this->max_duration;

		// The TTL is a single byte, there is no hop beyond 255.
		$max_hops = min( $max_hops, 255 );

		for ( $ttl = 1; $ttl <= $max_hops; $ttl++ ) {
			if ( microtime( true ) >= $deadline ) {
				break;
			}

			$hop = $this->probe_hop( $send_socket, $receive_socket, $destination_ip, $ttl, $identifier, $wait, $deadline );

			$hops[] = array(
				'hop'      => $ttl,
				'ip'       => $hop['ip'],
				'times_ms' => $hop['times_ms'],
			);

			if ( $hop['reached'] ) {
				break;
			}
		}

		socket_close( $send_socket );
		socket_close( $receive_socket );

		return $hops;
	}

	/**
	 * Send all probes for a single hop and collect the replies.
	 *
	 * @param Socket $send_socket    Socket used to send the probes.
	 * @param Socket $receive_socket Socket used to read ICMP replies.
	 * @param string $destination_ip The target IPv4 address.
	 * @param int    $ttl            TTL of this hop.
	 * @param int    $identifier     ICMP identifier of this run.
	 * @param int    $wait           Per-probe wait time in seconds.
	 * @param float  $deadline       Absolute deadline of the whole trace as a microtime value.
	 * @return array{ip:?string,times_ms:float[],reached:bool}
	 */
	private function probe_hop( Socket $send_socket, Socket $receive_socket, string $destination_ip, int $ttl, int $identifier, int $wait, float $deadline ): array {
		$hop_ip   = null;
		$times_ms = array();
		$reached  = false;

		for ( $probe = 0; $probe < $this->probes; $probe++ ) {
			$sequence = ( ( $ttl * 100 ) + $probe ) & 0xFFFF;
			$packet   = $this->build_probe( $destination_ip, $ttl, $identifier, $sequence );

			$started = microtime( true );

			if ( $started >= $deadline ) {
				break;
			}

			// phpcs:ignore WordPress.PHP.NoSilencedErrors -- a failed send is handled as a missing reply.
			if ( false === @socket_sendto( $send_socket, $packet, strlen( $packet ), 0, $destination_ip, 0 ) ) {
				continue;
			}

			$reply = $this->receive_reply( $receive_socket, $identifier, $sequence, min( $started + $wait, $deadline ) );

			if ( null === $reply ) {
				continue;
			}

			$times_ms[] = round( ( microtime( true ) - $started ) * 1000, 2 );
			$hop_ip     = $reply['ip'];

			if ( $reply['final'] ) {
				$reached = true;
			}
		}

		return array(
			'ip'       => $hop_ip,
			'times_ms' => $times_ms,
			'reached'  => $reached,
		);
	}

	/**
	 * Wait for a reply that belongs to this probe, until the deadline.
	 *
	 * Replies caused by other processes on the same host land on the same
	 * socket, so everything that does not carry our identifier and sequence
	 * is discarded and the wait continues.
	 *
	 * @param Socket $receive_socket Socket to read from.
	 * @param int    $identifier     ICMP identifier of this run.
	 * @param int    $sequence       ICMP sequence of this probe.
	 * @param float  $deadline       Absolute deadline as a microtime value.
	 * @return array{ip:string,final:bool}|null
	 */
	private function receive_reply( Socket $receive_socket, int $identifier, int $sequence, float $deadline ): ?array {
		while ( true ) {
			$remaining = $deadline - microtime( true );

			if ( $remaining <= 0 ) {
				return null;
			}

			$read   = array( $receive_socket );
			$write  = null;
			$except = null;

			$seconds      = (int) $remaining;
			$microseconds = (int) ( ( $remaining - $seconds ) * 1000000 );

			// phpcs:ignore WordPress.PHP.NoSilencedErrors -- an interrupted select is handled as a missing reply.
			$ready = @socket_select( $read, $write, $except, $seconds, $microseconds );

			if ( false === $ready || 0 === $ready ) {
				return null;
			}

			$buffer      = '';
			$source_ip   = '';
			$source_port = 0;

			// phpcs:ignore WordPress.PHP.NoSilencedErrors -- see above.
			if ( false === @socket_recvfrom( $receive_socket, $buffer, 65535, 0, $source_ip, $source_port ) ) {
				return null;
			}

			$parsed = $this->parse_reply( (string) $buffer, $identifier, $sequence );

			if ( null !== $parsed ) {
				return array(
					'ip'    => $source_ip,
					'final' => $parsed['final'],
				);
			}
		}
	}

	/**
	 * Build one probe packet: IP header plus ICMP echo request.
	 *
	 * @param string $destination_ip The target IPv4 address.
	 * @param int    $ttl            TTL to set in the IP header.
	 * @param int    $identifier     ICMP identifier.
	 * @param int    $sequence       ICMP sequence.
	 * @return string
	 */
	protected function build_probe( string $destination_ip, int $ttl, int $identifier, int $sequence ): string {
		$icmp = $this->build_echo_request( $identifier, $sequence );

		$destination = inet_pton( $destination_ip );

		$ip_header = pack(
			'CCnnnCCna4a4',
			0x45,                        // Version 4, header length 5 words.
			0,                           // Type of service.
			20 + strlen( $icmp ),        // Total length.
			$identifier,                 // Identification.
			0,                           // Flags and fragment offset.
			$ttl,                        // Time to live - the point of the whole exercise.
			self::PROTOCOL_ICMP,         // Protocol.
			0,                           // Header checksum, filled in by the kernel.
			"\x00\x00\x00\x00",          // Source address, filled in by the kernel.
			false !== $destination ? $destination : "\x00\x00\x00\x00"
		);

		return $ip_header . $icmp;
	}

	/**
	 * Build an ICMP echo request including its checksum.
	 *
	 * Unlike the IP header checksum, the kernel does not compute this one.
	 *
	 * @param int $identifier ICMP identifier.
	 * @param int $sequence   ICMP sequence.
	 * @return string
	 */
	protected function build_echo_request( int $identifier, int $sequence ): string {
		$message = pack( 'CCnnn', self::ICMP_ECHO_REQUEST, 0, 0, $identifier, $sequence ) . self::PAYLOAD;

		return substr_replace( $message, pack( 'n', $this->checksum( $message ) ), 2, 2 );
	}

	/**
	 * Check whether a received packet is a reply to one of our probes.
	 *
	 * An ICMP error message carries the IP header of the offending packet
	 * plus at least its first 8 bytes - which is exactly the ICMP header we
	 * sent, so identifier and sequence can be read back from it.
	 *
	 * @param string $packet     The raw packet, starting with its IP header.
	 * @param int    $identifier The identifier to match.
	 * @param int    $sequence   The sequence to match.
	 * @return array{final:bool}|null Null if the packet is unrelated.
	 */
	protected function parse_reply( string $packet, int $identifier, int $sequence ): ?array {
		$icmp = $this->strip_ip_header( $packet );

		if ( strlen( $icmp ) < 8 ) {
			return null;
		}

		$type = ord( $icmp[0] );

		if ( self::ICMP_ECHO_REPLY === $type ) {
			return $this->matches( substr( $icmp, 4, 4 ), $identifier, $sequence ) ? array( 'final' => true ) : null;
		}

		if ( self::ICMP_TIME_EXCEEDED !== $type && self::ICMP_UNREACHABLE !== $type ) {
			return null;
		}

		// The offending packet starts after the 8 byte ICMP error header.
		$embedded      = $this->strip_ip_header( substr( $icmp, 8 ) );
		$is_our_packet = strlen( $embedded ) >= 8
			&& self::ICMP_ECHO_REQUEST === ord( $embedded[0] )
			&& $this->matches( substr( $embedded, 4, 4 ), $identifier, $sequence );

		if ( ! $is_our_packet ) {
			return null;
		}

		// An unreachable message means the probe will never get any closer.
		return array( 'final' => self::ICMP_UNREACHABLE === $type );
	}

	/**
	 * Remove the IPv4 header from a packet, honouring its header length.
	 *
	 * @param string $packet The packet, starting with its IP header.
	 * @return string
	 */
	private function strip_ip_header( string $packet ): string {
		if ( '' === $packet ) {
			return '';
		}

		$header_length = ( ord( $packet[0] ) & 0x0F ) * 4;

		if ( $header_length < 20 || strlen( $packet ) < $header_length ) {
			return '';
		}

		return substr( $packet, $header_length );
	}

	/**
	 * Compare the identifier/sequence pair of an ICMP header.
	 *
	 * @param string $header_part The 4 bytes holding identifier and sequence.
	 * @param int    $identifier  The identifier to match.
	 * @param int    $sequence    The sequence to match.
	 * @return bool
	 */
	private function matches( string $header_part, int $identifier, int $sequence ): bool {
		if ( 4 !== strlen( $header_part ) ) {
			return false;
		}

		$unpacked = unpack( 'nidentifier/nsequence', $header_part );

		if ( false === $unpacked ) {
			return false;
		}

		return $unpacked['identifier'] === $identifier && $unpacked['sequence'] === $sequence;
	}

	/**
	 * Compute the internet checksum (RFC 1071) of a block of data.
	 *
	 * @param string $data The data to sum over.
	 * @return int
	 */
	protected function checksum( string $data ): int {
		if ( 0 !== strlen( $data ) % 2 ) {
			$data .= "\x00";
		}

		$words = unpack( 'n*', $data );

		if ( false === $words ) {
			return 0;
		}

		$sum = array_sum( $words );

		while ( $sum >> 16 ) {
			$sum = ( $sum & 0xFFFF ) + ( $sum >> 16 );
		}

		return ~$sum & 0xFFFF;
	}
}
