<?php
/**
 * File to test the reusable HTTP client trait.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;
use TcpAnalyzer\PHPUnitTests\Support\Http_Client_Double;
use TcpAnalyzer\PHPUnitTests\Support\Local_Http_Server;
use TcpAnalyzer\Traits\Http_Client;
use TcpAnalyzer\Traits\Target_Guard;

/**
 * Tests for TcpAnalyzer\Traits\Http_Client.
 *
 * Both implementations - curl and the stream fallback - are exercised
 * against a real HTTP server on the loopback interface, see
 * Local_Http_Server for the why. function_exists() is stubbed in the
 * TcpAnalyzer\Traits namespace to force the stream path regardless of the
 * machine the suite runs on.
 */
#[CoversTrait( Http_Client::class )]
#[CoversTrait( Target_Guard::class )]
final class Http_Client_Test extends TestCase {

	/**
	 * The local server all requests go to.
	 *
	 * @var Local_Http_Server|null
	 */
	private static ?Local_Http_Server $server = null;

	/**
	 * The double under test.
	 *
	 * @var Http_Client_Double
	 */
	private Http_Client_Double $client;

	/**
	 * Temporary files created during a test.
	 *
	 * @var string[]
	 */
	private array $temp_files = array();

	/**
	 * {@inheritDoc}
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		$server = new Local_Http_Server();

		self::$server = $server->start() ? $server : null;
	}

	/**
	 * {@inheritDoc}
	 */
	public static function tearDownAfterClass(): void {
		if ( null !== self::$server ) {
			self::$server->stop();
		}

		self::$server = null;

		parent::tearDownAfterClass();
	}

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->client = new Http_Client_Double();

		if ( null !== self::$server ) {
			self::$server->reset_hits();
		}
	}

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		FunctionMocks::reset();

		// Remove the proxy a test may have put into the environment.
		putenv( 'http_proxy' );

		foreach ( $this->temp_files as $temp_file ) {
			if ( is_file( $temp_file ) ) {
				unlink( $temp_file );
			}
		}

		$this->temp_files = array();

		parent::tearDown();
	}

	/**
	 * Both implementations, as a data provider.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_transports(): array {
		return array(
			'curl'   => array( 'curl' ),
			'stream' => array( 'stream' ),
		);
	}

	/**
	 * The implementation is chosen by the availability of curl.
	 *
	 * @return void
	 */
	#[Test]
	public function decides_by_the_availability_of_curl(): void {
		$checked = array();

		FunctionMocks::set_for_traits(
			'function_exists',
			static function ( string $function ) use ( &$checked ): bool {
				$checked[] = $function;

				return false;
			}
		);

		$this->client->request( $this->server()->url( '/ip' ) );

		$this->assertSame( array( 'curl_init' ), $checked );
	}

	/**
	 * A plain request returns the body and the status code.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function returns_the_body_and_the_status_code( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( $this->server()->url( '/ip' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( '203.0.113.42', $response['body'] );
		$this->assertSame( 200, $response['http_code'] );
		$this->assertNull( $response['error_code'] );
		$this->assertArrayHasKey( 'total_ms', $response['timing'] );
		$this->assertIsFloat( $response['timing']['total_ms'] );
		$this->assertGreaterThanOrEqual( 0.0, $response['timing']['total_ms'] );
		$this->assertSame( array( 'GET /ip' ), $this->server()->get_hits() );
	}

	/**
	 * A HEAD-only request is sent as such.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function sends_a_head_request_when_asked_to( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( $this->server()->url( '/ip' ), 10, true );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 200, $response['http_code'] );
		$this->assertSame( '', $response['body'] );
		$this->assertSame( array( 'HEAD /ip' ), $this->server()->get_hits() );
	}

	/**
	 * curl reports the detailed timing, the stream fallback only the total.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_timing_each_implementation_can_measure(): void {
		$this->use_transport( 'curl' );

		$this->assertSame(
			array( 'dns_ms', 'connect_ms', 'tls_ms', 'ttfb_ms', 'total_ms' ),
			array_keys( $this->client->request( $this->server()->url( '/ip' ) )['timing'] )
		);

		$this->use_transport( 'stream' );

		$this->assertSame(
			array( 'total_ms' ),
			array_keys( $this->client->request( $this->server()->url( '/ip' ) )['timing'] )
		);
	}

	/**
	 * A 4xx/5xx response is a response, not a failed request - in both
	 * implementations.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function reports_the_status_code_of_an_error_response( string $transport ): void {
		$this->use_transport( $transport );

		foreach ( array( 404, 418, 500 ) as $status_code ) {
			$response = $this->client->request( $this->server()->url( '/status/' . $status_code ) );

			$this->assertTrue( $response['success'] );
			$this->assertSame( $status_code, $response['http_code'] );
			$this->assertSame( 'status ' . $status_code, $response['body'] );
			$this->assertNull( $response['error_code'] );
		}
	}

	/**
	 * A body longer than the limit is cut off at the limit, the request
	 * still succeeds. A server cannot exhaust the memory with its response.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function cuts_the_body_off_at_the_limit( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->max_body_bytes = 1000;

		$response = $this->client->request( $this->server()->url( '/big?bytes=50000' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 200, $response['http_code'] );
		$this->assertSame( str_repeat( 'x', 1000 ), $response['body'] );
		$this->assertNull( $response['error_code'] );

		// A body that fits is returned completely.
		$response = $this->client->request( $this->server()->url( '/big?bytes=1000' ) );

		$this->assertSame( str_repeat( 'x', 1000 ), $response['body'] );

		$response = $this->client->request( $this->server()->url( '/big?bytes=999' ) );

		$this->assertSame( str_repeat( 'x', 999 ), $response['body'] );
	}

	/**
	 * Out of the box not more than 1 MB of a body is read.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function reads_one_megabyte_of_a_body_by_default( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( $this->server()->url( '/big?bytes=3000000' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 1048576, strlen( (string) $response['body'] ) );
	}

	/**
	 * The timeout limits the whole request. A server that keeps sending a
	 * byte every now and then - so every single read is in time - cannot
	 * keep the request open any longer.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function gives_up_on_a_dripping_response_after_the_timeout( string $transport ): void {
		$this->use_transport( $transport );

		$started  = microtime( true );
		$response = $this->client->request( $this->server()->url( '/drip?seconds=6' ), 1 );
		$elapsed  = microtime( true ) - $started;

		$this->assertFalse( $response['success'] );
		$this->assertNull( $response['body'] );
		$this->assertSame( 'curl' === $transport ? 'curl_errno_28' : 'request_failed', $response['error_code'] );
		$this->assertLessThan( 3.0, $elapsed );
	}

	/**
	 * Credentials are removed from a URL before it goes into a result.
	 *
	 * @return void
	 */
	#[Test]
	public function removes_the_credentials_from_a_url(): void {
		$urls = array(
			'https://user:secret@example.com/path?a=b' => 'https://example.com/path?a=b',
			'http://user@example.com:8080/'            => 'http://example.com:8080/',
			'HTTP://user:p%40ss@example.com'           => 'HTTP://example.com',
			'https://example.com/path'                 => 'https://example.com/path',
			'https://example.com/?mail=a@b.de'         => 'https://example.com/?mail=a@b.de',
			'https://example.com/a@b'                  => 'https://example.com/a@b',
			'https://example.com#a@b'                  => 'https://example.com#a@b',
			'not a url'                                => 'not a url',
			''                                         => '',
		);

		foreach ( $urls as $url => $expected ) {
			$this->assertSame( $expected, $this->client->without_credentials( (string) $url ) );
		}
	}

	/**
	 * A redirect is reported, not followed: the target of the redirect is
	 * never requested. Otherwise a harmless looking URL could send the
	 * request on to an internal address.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function does_not_follow_a_redirect( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( $this->server()->url( '/redirect?to=' . rawurlencode( $this->server()->url( '/internal' ) ) ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 302, $response['http_code'] );
		$this->assertNotSame( 'internal', $response['body'] );
		$this->assertCount( 1, $this->server()->get_hits() );
		$this->assertStringStartsWith( 'GET /redirect?', $this->server()->get_hits()[0] );
	}

	/**
	 * Only http:// and https:// URLs are requested. Most notably the stream
	 * fallback must not open local files or other stream wrappers.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function refuses_any_other_scheme( string $transport ): void {
		$this->use_transport( $transport );

		$port = $this->server()->get_port();
		$urls = array(
			'file://' . $this->temp_file( '203.0.113.42' ),
			'FILE://' . $this->temp_file( '203.0.113.42' ),
			'php://memory',
			'data://text/plain,203.0.113.42',
			'ftp://127.0.0.1:' . $port . '/ip',
			'gopher://127.0.0.1:' . $port . '/_GET%20/ip',
			'dict://127.0.0.1:' . $port . '/',
		);

		foreach ( $urls as $url ) {
			$response = $this->client->request( $url );

			$this->assertFalse( $response['success'], $url );
			$this->assertNull( $response['body'], $url );
			$this->assertSame( 'url_scheme_not_allowed', $response['error_code'], $url );
		}

		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * The scheme is not case-sensitive.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function accepts_the_scheme_in_any_case( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( 'HTTP://127.0.0.1:' . $this->server()->get_port() . '/ip' );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 200, $response['http_code'] );
	}

	/**
	 * Anything that is not a complete URL is refused before a request is
	 * made - including a URL carrying a line break, which could otherwise
	 * smuggle a header into the request.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function refuses_a_malformed_url( string $transport ): void {
		$this->use_transport( $transport );

		$base = $this->server()->url( '/ip' );
		$urls = array(
			'',
			'127.0.0.1/ip',
			'//127.0.0.1/ip',
			'http:///ip',
			' ' . $base,
			$base . "\n",
			$base . "\r\nX-Injected: 1",
			$base . '?a=b c',
			$base . "\0",
			// Port 0 is no port, the stream wrapper would silently use the default port instead.
			'http://127.0.0.1:0/ip',
		);

		foreach ( $urls as $url ) {
			$response = $this->client->request( $url );

			$this->assertFalse( $response['success'], (string) json_encode( $url ) );
			$this->assertSame( 'invalid_url', $response['error_code'], (string) json_encode( $url ) );
		}

		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * A failing request never throws, it returns a structured failure.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function returns_a_structured_failure_instead_of_throwing( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( 'http://127.0.0.1:' . $this->server()->find_free_port() . '/', 2 );

		$this->assertFalse( $response['success'] );
		$this->assertNull( $response['body'] );
		$this->assertNull( $response['http_code'] );
		$this->assertSame( 'curl' === $transport ? 'curl_errno_7' : 'request_failed', $response['error_code'] );
	}

	/**
	 * The returned array always has the documented shape, in every outcome.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function always_returns_the_documented_response_shape( string $transport ): void {
		$this->use_transport( $transport );

		$expected_keys = array( 'success', 'body', 'http_code', 'timing', 'error_code' );

		$this->assertSame( $expected_keys, array_keys( $this->client->request( $this->server()->url( '/ip' ) ) ) );
		$this->assertSame( $expected_keys, array_keys( $this->client->request( 'http://127.0.0.1:' . $this->server()->find_free_port() . '/', 2 ) ) );
		$this->assertSame( $expected_keys, array_keys( $this->client->request( 'file:///nope/' . uniqid() ) ) );
		$this->assertSame( $expected_keys, array_keys( $this->client->request( 'not a url' ) ) );
	}

	/**
	 * Without a target filter nothing changes: the client does not resolve
	 * the host on its own.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function does_not_resolve_the_host_without_a_target_filter( string $transport ): void {
		$this->use_transport( $transport );

		$response = $this->client->request( $this->server()->url( '/ip' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( array(), $this->client->resolve_calls );
	}

	/**
	 * The filter is asked with the host, the IP it resolved to and the port
	 * of the URL - the default port of the scheme if the URL has none.
	 *
	 * @return void
	 */
	#[Test]
	public function asks_the_filter_with_host_ip_and_port(): void {
		$asked = array();

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '192.0.2.10' ) ) );
		$this->client->filter   = static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
			$asked[] = array( $host, $ip, $port );

			return false;
		};

		$this->client->request( 'http://pinned.test:8080/path' );
		$this->client->request( 'http://pinned.test/path' );
		$this->client->request( 'https://pinned.test/path' );

		$this->assertSame(
			array(
				array( 'pinned.test', '192.0.2.10', 8080 ),
				array( 'pinned.test', '192.0.2.10', 80 ),
				array( 'pinned.test', '192.0.2.10', 443 ),
			),
			$asked
		);
	}

	/**
	 * A rejected target is never requested.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function does_not_request_a_rejected_target( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->filter = static fn( string $host, string $ip, ?int $port ): bool => false;

		$response = $this->client->request( $this->server()->url( '/ip' ) );

		$this->assertFalse( $response['success'] );
		$this->assertNull( $response['body'] );
		$this->assertSame( 'target_rejected', $response['error_code'] );
		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * Only an exact true accepts a target, a filter returning anything else
	 * - e.g. by forgetting the return statement - rejects it.
	 *
	 * @return void
	 */
	#[Test]
	public function accepts_a_target_only_on_an_exact_true(): void {
		foreach ( array( null, 1, 'yes', false ) as $answer ) {
			$this->client->filter = static fn( string $host, string $ip, ?int $port ): mixed => $answer;

			$this->assertSame( 'target_rejected', $this->client->request( $this->server()->url( '/ip' ) )['error_code'] );
		}

		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * An accepted IP address as host is requested as it is.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function requests_an_accepted_ip_address( string $transport ): void {
		$this->use_transport( $transport );

		$asked = array();

		$this->client->filter = static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
			$asked[] = array( $host, $ip, $port );

			return true;
		};

		$response = $this->client->request( $this->server()->url( '/ip' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( '203.0.113.42', $response['body'] );
		$this->assertSame( array( array( '127.0.0.1', '127.0.0.1', $this->server()->get_port() ) ), $asked );
	}

	/**
	 * The connection goes to the IP the filter has accepted - the host is
	 * not resolved a second time. Proven with a host name no DNS knows: the
	 * request can only succeed if the pinned IP is used. The server still
	 * sees the original host.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function connects_to_the_ip_the_filter_has_accepted( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => '127.0.0.1' === $ip;

		$response = $this->client->request( $this->server()->url( '/echo', 'pinned.test' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( 200, $response['http_code'] );

		$seen = json_decode( (string) $response['body'], true );

		$this->assertIsArray( $seen );
		$this->assertSame( 'pinned.test:' . $this->server()->get_port(), $seen['host'] );
		$this->assertSame(
			array(
				array(
					'host'   => 'pinned.test',
					'family' => 4,
				),
			),
			$this->client->resolve_calls
		);
	}

	/**
	 * The pin also holds against a name that does resolve - to somewhere
	 * else: "localhost" would lead to the local server, but the accepted IP
	 * is one where nothing listens. If the name were resolved a second time,
	 * the server would see the request.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function does_not_resolve_the_host_a_second_time( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->resolves = array( 'localhost' => array( 4 => array( '127.0.0.2' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => true;

		$response = $this->client->request( $this->server()->url( '/ip', 'localhost' ), 2 );

		$this->assertFalse( $response['success'] );
		$this->assertNull( $response['body'] );
		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * A timeout curl does not accept must not cost the pin: curl stops
	 * applying its options at the first one it rejects.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function keeps_the_pin_with_a_timeout_out_of_range( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->resolves = array( 'localhost' => array( 4 => array( '127.0.0.2' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => true;

		// Without the clamp curl would refuse -1 and, from there on, skip every option that follows.
		foreach ( array( -1, 0 ) as $timeout ) {
			$response = $this->client->request( $this->server()->url( '/ip', 'localhost' ), $timeout );

			$this->assertFalse( $response['success'], (string) $timeout );
		}

		$this->assertSame( array(), $this->server()->get_hits() );
	}

	/**
	 * Without a filter, a timeout out of range is brought into range
	 * instead of breaking the request.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function brings_a_timeout_out_of_range_into_range( string $transport ): void {
		$this->use_transport( $transport );

		foreach ( array( -1, 0, PHP_INT_MAX ) as $timeout ) {
			$response = $this->client->request( $this->server()->url( '/ip' ), $timeout, true );

			$this->assertTrue( $response['success'], (string) $timeout );
			$this->assertSame( 200, $response['http_code'], (string) $timeout );
		}

		$this->assertSame( array( 'HEAD /ip', 'HEAD /ip', 'HEAD /ip' ), $this->server()->get_hits() );
	}

	/**
	 * With a filter the request does not go through a proxy from the
	 * environment, it goes straight to the accepted IP. The proxy configured
	 * here does not even exist - the request can only succeed if it is
	 * ignored.
	 *
	 * @return void
	 */
	#[Test]
	public function ignores_a_proxy_from_the_environment_with_a_target_filter(): void {
		$this->use_transport( 'curl' );

		putenv( 'http_proxy=http://127.0.0.1:' . $this->server()->find_free_port() );

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => true;

		$response = $this->client->request( $this->server()->url( '/ip', 'pinned.test' ), 2 );

		$this->assertTrue( $response['success'] );
		$this->assertSame( '203.0.113.42', $response['body'] );
	}

	/**
	 * A libcurl too old to pin a connection is not used for a request that
	 * has to be pinned - the stream implementation takes over, recognizable
	 * by its timing. Without a filter curl is used as before.
	 *
	 * @return void
	 */
	#[Test]
	public function leaves_a_pinned_request_to_the_stream_implementation_if_curl_cannot_pin(): void {
		$this->use_transport( 'curl' );

		FunctionMocks::set_for_traits( 'defined', static fn( string $constant_name ): bool => 'CURLOPT_CONNECT_TO' !== $constant_name && defined( $constant_name ) );

		$this->assertArrayHasKey( 'connect_ms', $this->client->request( $this->server()->url( '/ip' ) )['timing'] );

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => true;

		$response = $this->client->request( $this->server()->url( '/ip', 'pinned.test' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( '203.0.113.42', $response['body'] );
		$this->assertSame( array( 'total_ms' ), array_keys( $response['timing'] ) );
	}

	/**
	 * Path, query and credentials of the URL survive the pinning.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function keeps_path_query_and_credentials_of_a_pinned_url( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->filter   = static fn( string $host, string $ip, ?int $port ): bool => true;

		$response = $this->client->request( 'http://user:p%40ss@pinned.test:' . $this->server()->get_port() . '/echo?a=1&b=two#fragment' );

		$this->assertTrue( $response['success'] );

		$seen = json_decode( (string) $response['body'], true );

		$this->assertIsArray( $seen );
		$this->assertSame( '/echo?a=1&b=two', $seen['uri'] );
		$this->assertSame( 'user', $seen['user'] );
		$this->assertSame( 'p@ss', $seen['pass'] );
	}

	/**
	 * A redirect is not followed with a filter either - the filter is not
	 * even asked about its target.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function does_not_follow_a_redirect_of_a_pinned_target( string $transport ): void {
		$this->use_transport( $transport );

		$asked = 0;

		$this->client->resolves = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->filter   = static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
			++$asked;

			return true;
		};

		$response = $this->client->request( $this->server()->url( '/redirect?to=' . rawurlencode( $this->server()->url( '/internal' ) ), 'pinned.test' ) );

		$this->assertSame( 302, $response['http_code'] );
		$this->assertSame( 1, $asked );
		$this->assertCount( 1, $this->server()->get_hits() );
	}

	/**
	 * IPv6 addresses are only looked up - and offered to the filter - if no
	 * IPv4 address has been accepted.
	 *
	 * @return void
	 */
	#[Test]
	public function offers_ipv6_addresses_after_the_ipv4_ones(): void {
		$asked = array();

		$this->client->resolves = array(
			'dual.test' => array(
				4 => array( '192.0.2.10', '192.0.2.11' ),
				6 => array( '2001:db8::1' ),
			),
		);
		$this->client->filter   = static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
			$asked[] = $ip;

			return false;
		};

		$response = $this->client->request( 'http://dual.test/' );

		$this->assertSame( 'target_rejected', $response['error_code'] );
		$this->assertSame( array( '192.0.2.10', '192.0.2.11', '2001:db8::1' ), $asked );
	}

	/**
	 * A host that does not resolve at all is reported as such, the filter
	 * is not asked.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_host_that_does_not_resolve(): void {
		$this->client->resolves = array( 'gone.test' => array() );
		$this->client->filter   = static function ( string $host, string $ip, ?int $port ): bool {
			TestCase::fail( 'The filter must not be asked without an IP.' );
		};

		$response = $this->client->request( 'http://gone.test/' );

		$this->assertFalse( $response['success'] );
		$this->assertSame( 'dns_resolution_failed', $response['error_code'] );
	}

	/**
	 * With a filter, a host that is neither a plain name nor an IP address
	 * is refused: it could not be pinned reliably.
	 *
	 * @return void
	 */
	#[Test]
	public function refuses_an_unusual_host_with_a_target_filter(): void {
		$this->client->filter = static fn( string $host, string $ip, ?int $port ): bool => true;

		$urls = array(
			'http://-evil.test/',
			'http://ex%61mple.test/',
			'http://exa mple.test/',
			'http://münchen.test/',
			// Other notations of 127.0.0.1: a name to PHP's resolver, an IP address to curl.
			'http://2130706433/',
			'http://127.1/',
			'http://0x7f000001/',
			'http://0x7f.1/',
		);

		foreach ( $urls as $url ) {
			$response = $this->client->request( $url );

			$this->assertFalse( $response['success'], $url );
			$this->assertContains( $response['error_code'], array( 'invalid_host', 'invalid_url' ), $url );
		}

		$this->assertSame( array(), $this->client->resolve_calls );
	}

	/**
	 * The time the lookup took is part of the reported timing, although it
	 * happens before the actual request once a filter is set.
	 *
	 * @param string $transport The implementation to use.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_transports' )]
	public function includes_the_lookup_in_the_timing_of_a_pinned_request( string $transport ): void {
		$this->use_transport( $transport );

		$this->client->resolves         = array( 'pinned.test' => array( 4 => array( '127.0.0.1' ) ) );
		$this->client->resolve_delay_us = 30000;
		$this->client->filter           = static fn( string $host, string $ip, ?int $port ): bool => true;

		$response = $this->client->request( $this->server()->url( '/ip', 'pinned.test' ) );

		$this->assertTrue( $response['success'] );
		$this->assertGreaterThanOrEqual( 30.0, $response['timing']['total_ms'] );

		if ( 'curl' === $transport ) {
			$this->assertGreaterThanOrEqual( 30.0, $response['timing']['dns_ms'] );
			$this->assertGreaterThanOrEqual( $response['timing']['dns_ms'], $response['timing']['connect_ms'] );
			$this->assertSame( 0.0, $response['timing']['tls_ms'] );
		}
	}

	/**
	 * Return the local server, or skip the test if it could not be started.
	 *
	 * @return Local_Http_Server
	 */
	private function server(): Local_Http_Server {
		if ( null === self::$server ) {
			$this->markTestSkipped( 'The local HTTP server could not be started.' );
		}

		return self::$server;
	}

	/**
	 * Force one of the two implementations.
	 *
	 * @param string $transport "curl" or "stream".
	 * @return void
	 */
	private function use_transport( string $transport ): void {
		FunctionMocks::reset();

		if ( 'curl' === $transport ) {
			if ( ! function_exists( 'curl_init' ) ) {
				$this->markTestSkipped( 'The curl extension is not available.' );
			}

			return;
		}

		// Report curl as unavailable, leave everything else alone.
		FunctionMocks::set_for_traits( 'function_exists', static fn( string $function ): bool => 'curl_init' !== $function && function_exists( $function ) );
	}

	/**
	 * Create a temporary file with the given content and return its path.
	 *
	 * @param string $content Content of the file.
	 * @return string
	 */
	private function temp_file( string $content ): string {
		$path = (string) tempnam( sys_get_temp_dir(), 'tcp-analyzer-' );
		file_put_contents( $path, $content );

		$this->temp_files[] = $path;

		return $path;
	}
}
