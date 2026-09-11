<?php
/**
 * File to test the raw socket based traceroute method.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;
use TcpAnalyzer\PHPUnitTests\Support\Socket_Method_Double;
use TcpAnalyzer\Traceroute\Socket_Method;

/**
 * Tests for TcpAnalyzer\Traceroute\Socket_Method.
 *
 * Sending and receiving needs CAP_NET_RAW plus a real peer and is therefore
 * not unit-testable. What is tested here is everything that decides whether
 * the method works at all: the availability check, the byte layout of the
 * probe packets, and the matching of incoming replies - the parts where a
 * mistake is silent and would only show up as "no hops" in production.
 */
#[CoversClass( Socket_Method::class )]
final class Socket_Method_Test extends TestCase {

	/**
	 * The method under test.
	 *
	 * @var Socket_Method_Double
	 */
	private Socket_Method_Double $method;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->method = new Socket_Method_Double();
	}

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		FunctionMocks::reset();

		parent::tearDown();
	}

	/**
	 * The slug is reported in the result data, so it is part of the contract.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_published_slug(): void {
		$this->assertSame( 'socket', $this->method->get_slug() );
	}

	/**
	 * Without ext-sockets nothing works, and no socket call is attempted.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_missing_sockets_extension(): void {
		FunctionMocks::set_for_traceroute( 'extension_loaded', static fn( string $extension ): bool => 'sockets' !== $extension );
		FunctionMocks::set_for_traceroute(
			'socket_create',
			static function ( int $domain, int $type, int $protocol ) {
				TestCase::fail( 'socket_create() must not be called without ext-sockets.' );
			}
		);

		$this->assertSame( 'sockets_unavailable', $this->method->check_availability() );
	}

	/**
	 * A denied raw socket is the normal case on shared hosting and gets its
	 * own code, so the consuming project can say what is missing.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_denied_raw_socket(): void {
		FunctionMocks::set_for_traceroute( 'extension_loaded', static fn( string $extension ): bool => true );
		FunctionMocks::set_for_traceroute( 'socket_create', static fn( int $domain, int $type, int $protocol ) => false );

		$this->assertSame( 'raw_socket_denied', $this->method->check_availability() );
	}

	/**
	 * With a raw socket obtainable, the method reports itself as available.
	 *
	 * @return void
	 */
	#[Test]
	public function is_available_when_a_raw_socket_can_be_opened(): void {
		$requested = array();

		FunctionMocks::set_for_traceroute( 'extension_loaded', static fn( string $extension ): bool => true );
		FunctionMocks::set_for_traceroute(
			'socket_create',
			static function ( int $domain, int $type, int $protocol ) use ( &$requested ) {
				$requested = array( $domain, $type, $protocol );

				// A TCP socket needs no privileges and stands in for the raw one.
				return socket_create( AF_INET, SOCK_STREAM, SOL_TCP );
			}
		);

		$this->assertNull( $this->method->check_availability() );
		$this->assertSame( array( AF_INET, SOCK_RAW, 1 ), $requested );
	}

	/**
	 * The ICMP echo request has the layout the RFC prescribes.
	 *
	 * @return void
	 */
	#[Test]
	public function builds_a_well_formed_echo_request(): void {
		$message = $this->method->expose_build_echo_request( 4711, 100 );

		$header = unpack( 'Ctype/Ccode/nchecksum/nidentifier/nsequence', $message );

		$this->assertIsArray( $header );
		$this->assertSame( 8, $header['type'], 'Type 8 is an echo request.' );
		$this->assertSame( 0, $header['code'] );
		$this->assertSame( 4711, $header['identifier'] );
		$this->assertSame( 100, $header['sequence'] );
		$this->assertSame( 40, strlen( $message ), '8 byte header plus 32 byte payload.' );
	}

	/**
	 * The checksum is the one the kernel does not compute for us. A correct
	 * checksum makes the sum over the whole message come out as zero.
	 *
	 * @param int $identifier ICMP identifier.
	 * @param int $sequence   ICMP sequence.
	 * @param int $expected   Independently computed expected checksum.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_echo_checksums' )]
	public function computes_the_icmp_checksum( int $identifier, int $sequence, int $expected ): void {
		$message = $this->method->expose_build_echo_request( $identifier, $sequence );

		$header = unpack( 'Ctype/Ccode/nchecksum', $message );

		$this->assertIsArray( $header );
		$this->assertSame( $expected, $header['checksum'] );
		$this->assertSame( 0, $this->method->expose_checksum( $message ), 'A valid message sums to zero.' );
	}

	/**
	 * Data provider for computes_the_icmp_checksum().
	 *
	 * Expected values computed independently with a reference implementation
	 * of RFC 1071.
	 *
	 * @return array<string,array{0:int,1:int,2:int}>
	 */
	public static function provide_echo_checksums(): array {
		return array(
			'first probe' => array( 4711, 100, 0x0e46 ),
			'lowest'      => array( 1, 1, 0x210f ),
			'highest'     => array( 65535, 65535, 0x2111 ),
		);
	}

	/**
	 * The checksum matches known RFC 1071 vectors, including the odd-length
	 * case that has to be padded.
	 *
	 * @param string $data     Input data.
	 * @param int    $expected Expected checksum.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_checksum_vectors' )]
	public function matches_known_checksum_vectors( string $data, int $expected ): void {
		$this->assertSame( $expected, $this->method->expose_checksum( $data ) );
	}

	/**
	 * Data provider for matches_known_checksum_vectors().
	 *
	 * @return array<string,array{0:string,1:int}>
	 */
	public static function provide_checksum_vectors(): array {
		return array(
			'empty'      => array( '', 65535 ),
			'zero word'  => array( "\x00\x00", 65535 ),
			'full word'  => array( "\xff\xff", 0 ),
			'odd length' => array( 'abc', 15261 ),
		);
	}

	/**
	 * The IP header carries the TTL - the whole point of the exercise - and
	 * the fields the kernel expects to find.
	 *
	 * @return void
	 */
	#[Test]
	public function builds_an_ip_header_with_the_given_ttl(): void {
		$packet = $this->method->expose_build_probe( '93.184.216.34', 7, 4711, 100 );

		$header = unpack( 'Cversion/Ctos/ntotal_length/nid/nflags/Cttl/Cprotocol/nchecksum/a4source/a4destination', $packet );

		$this->assertIsArray( $header );
		$this->assertSame( 0x45, $header['version'], 'IPv4 with a 20 byte header.' );
		$this->assertSame( 7, $header['ttl'] );
		$this->assertSame( 1, $header['protocol'], 'Protocol 1 is ICMP.' );
		$this->assertSame( 60, $header['total_length'], '20 byte IP header plus 40 byte ICMP message.' );
		$this->assertSame( 60, strlen( $packet ) );
		$this->assertSame( "\x00\x00\x00\x00", $header['source'], 'Filled in by the kernel.' );
		$this->assertSame( '93.184.216.34', inet_ntop( $header['destination'] ) );
		$this->assertSame( 0, $header['checksum'], 'Filled in by the kernel.' );
	}

	/**
	 * A "time exceeded" from a router on the path is our hop, and not the
	 * end of the trace.
	 *
	 * @return void
	 */
	#[Test]
	public function recognizes_a_time_exceeded_reply(): void {
		$reply = $this->icmp_error( 11, 4711, 100 );

		$this->assertSame( array( 'final' => false ), $this->method->expose_parse_reply( $reply, 4711, 100 ) );
	}

	/**
	 * An echo reply comes from the destination itself and ends the trace.
	 *
	 * @return void
	 */
	#[Test]
	public function recognizes_an_echo_reply_as_the_final_hop(): void {
		$reply = $this->ip_packet( pack( 'CCnnn', 0, 0, 0, 4711, 100 ) );

		$this->assertSame( array( 'final' => true ), $this->method->expose_parse_reply( $reply, 4711, 100 ) );
	}

	/**
	 * An unreachable message means the probe will get no closer, so the
	 * trace ends there too.
	 *
	 * @return void
	 */
	#[Test]
	public function treats_an_unreachable_reply_as_final(): void {
		$reply = $this->icmp_error( 3, 4711, 100 );

		$this->assertSame( array( 'final' => true ), $this->method->expose_parse_reply( $reply, 4711, 100 ) );
	}

	/**
	 * Replies caused by another process land on the same raw socket and must
	 * not be counted as ours.
	 *
	 * @param string $description What makes the packet foreign.
	 * @param int    $identifier  Identifier in the packet.
	 * @param int    $sequence    Sequence in the packet.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_foreign_replies' )]
	public function ignores_replies_that_are_not_ours( string $description, int $identifier, int $sequence ): void {
		$reply = $this->icmp_error( 11, $identifier, $sequence );

		$this->assertNull( $this->method->expose_parse_reply( $reply, 4711, 100 ), $description );
	}

	/**
	 * Data provider for ignores_replies_that_are_not_ours().
	 *
	 * @return array<string,array{0:string,1:int,2:int}>
	 */
	public static function provide_foreign_replies(): array {
		return array(
			'another process' => array( 'Different identifier.', 1234, 100 ),
			'another probe'   => array( 'Different sequence.', 4711, 101 ),
			'nothing matches' => array( 'Neither matches.', 1234, 101 ),
		);
	}

	/**
	 * ICMP types the method has no use for are discarded.
	 *
	 * @return void
	 */
	#[Test]
	public function ignores_unrelated_icmp_types(): void {
		$echo_request = $this->ip_packet( pack( 'CCnnn', 8, 0, 0, 4711, 100 ) );
		$redirect     = $this->ip_packet( pack( 'CCnnn', 5, 0, 0, 4711, 100 ) );

		$this->assertNull( $this->method->expose_parse_reply( $echo_request, 4711, 100 ) );
		$this->assertNull( $this->method->expose_parse_reply( $redirect, 4711, 100 ) );
	}

	/**
	 * Truncated or malformed packets must not produce warnings or matches.
	 *
	 * @return void
	 */
	#[Test]
	public function ignores_truncated_packets(): void {
		$this->assertNull( $this->method->expose_parse_reply( '', 4711, 100 ) );
		$this->assertNull( $this->method->expose_parse_reply( "\x45\x00\x00", 4711, 100 ) );
		$this->assertNull( $this->method->expose_parse_reply( $this->ip_packet( "\x0b\x00\x00\x00" ), 4711, 100 ) );
		$this->assertNull( $this->method->expose_parse_reply( $this->ip_packet( pack( 'CCnnn', 11, 0, 0, 0, 0 ) ), 4711, 100 ) );
	}

	/**
	 * An IP header can be longer than 20 bytes when it carries options - the
	 * header length field has to be honoured, not assumed.
	 *
	 * @return void
	 */
	#[Test]
	public function honours_the_ip_header_length(): void {
		$icmp   = pack( 'CCnnn', 0, 0, 0, 4711, 100 );
		$packet = $this->ip_packet( $icmp, 6 );

		$this->assertSame( 24, ( ord( $packet[0] ) & 0x0F ) * 4, 'Header with 4 bytes of options.' );
		$this->assertSame( array( 'final' => true ), $this->method->expose_parse_reply( $packet, 4711, 100 ) );
	}

	/**
	 * Build an ICMP error message carrying the offending packet.
	 *
	 * @param int $type       ICMP type, 11 for time exceeded, 3 for unreachable.
	 * @param int $identifier Identifier of the embedded echo request.
	 * @param int $sequence   Sequence of the embedded echo request.
	 * @return string
	 */
	private function icmp_error( int $type, int $identifier, int $sequence ): string {
		// The router echoes our IP header plus the first 8 bytes behind it.
		$embedded = $this->ip_packet( pack( 'CCnnn', 8, 0, 0, $identifier, $sequence ) );

		return $this->ip_packet( pack( 'CCnN', $type, 0, 0, 0 ) . $embedded );
	}

	/**
	 * Wrap a payload in an IPv4 header.
	 *
	 * @param string $payload       The payload to wrap.
	 * @param int    $header_words  Header length in 32 bit words, 5 without options.
	 * @return string
	 */
	private function ip_packet( string $payload, int $header_words = 5 ): string {
		$header = pack( 'CCnnnCCna4a4', 0x40 | $header_words, 0, 0, 0, 0, 64, 1, 0, "\x00\x00\x00\x00", "\x00\x00\x00\x00" );

		return str_pad( $header, $header_words * 4, "\x00" ) . $payload;
	}
}
