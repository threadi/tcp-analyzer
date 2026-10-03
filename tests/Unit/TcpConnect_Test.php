<?php
/**
 * File to test the raw TCP connect test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;
use TcpAnalyzer\Target_Filter;
use TcpAnalyzer\Tests\TcpConnect;

/**
 * Tests for TcpAnalyzer\Tests\TcpConnect.
 *
 * fsockopen() is stubbed in the TcpAnalyzer\Tests namespace, so no socket is
 * ever opened. A successful connect is simulated with an in-memory stream,
 * which the implementation can fclose() like a real socket.
 */
#[CoversClass( TcpConnect::class )]
final class TcpConnect_Test extends TestCase {

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		FunctionMocks::reset();

		parent::tearDown();
	}

	/**
	 * The slug is part of the public contract.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_published_slug(): void {
		$this->assertSame( 'tcp_connect', ( new TcpConnect() )->get_slug() );
	}

	/**
	 * On success the measured connect time is both the value and the
	 * duration of the result.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_connect_time_on_success(): void {
		$seen = array();

		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$seen ) {
				$seen = array(
					'host'    => $hostname,
					'port'    => $port,
					'timeout' => $timeout,
				);

				return fopen( 'php://memory', 'rb' );
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host' => 'example.com',
				'port' => 443,
			)
		);
		$test->run();

		$result = $test->get_result();

		$this->assertSame(
			array(
				'host'    => 'example.com',
				'port'    => 443,
				'timeout' => 8.0,
			),
			$seen
		);
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertIsFloat( $result->get_value() );
		$this->assertSame( $result->get_duration_ms(), $result->get_value() );
		$this->assertNull( $result->get_error_code() );
		$this->assertSame(
			array(
				'host' => 'example.com',
				'port' => 443,
			),
			$result->get_data()
		);
	}

	/**
	 * An immediate failure is classified as a refused connection.
	 *
	 * @return void
	 */
	#[Test]
	public function classifies_an_immediate_failure_as_refused(): void {
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) {
				$error_code    = 111;
				$error_message = 'Connection refused';

				return false;
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'    => 'example.com',
				'port'    => 9,
				'timeout' => 5,
			)
		);
		$test->run();

		$result = $test->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'tcp_connect_refused', $result->get_error_code() );
		$this->assertNull( $result->get_value() );
		$this->assertSame(
			array(
				'host'  => 'example.com',
				'port'  => 9,
				'errno' => 111,
			),
			$result->get_data()
		);
	}

	/**
	 * A failure that took (almost) the full timeout is classified as a
	 * timeout - the classification is by elapsed time, not by errno.
	 *
	 * @return void
	 */
	#[Test]
	public function classifies_a_slow_failure_as_timeout(): void {
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) {
				usleep( 120000 );

				$error_code = 0;

				return false;
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'    => 'example.com',
				'port'    => 443,
				'timeout' => 0.1,
			)
		);
		$test->run();

		$result = $test->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'tcp_connect_timeout', $result->get_error_code() );
		$this->assertGreaterThanOrEqual( 90.0, $result->get_duration_ms() );
	}

	/**
	 * The localized OS error message must never leak into the result, only
	 * the numeric errno does.
	 *
	 * @return void
	 */
	#[Test]
	public function does_not_leak_the_os_error_message(): void {
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) {
				$error_code    = 110;
				$error_message = 'Verbindungsaufbau abgelehnt';

				return false;
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host' => 'example.com',
				'port' => 443,
			)
		);
		$test->run();

		$encoded = (string) json_encode( $test->get_result()->to_array() );

		$this->assertSame( array( 'host', 'port', 'errno' ), array_keys( $test->get_result()->get_data() ) );
		$this->assertStringNotContainsString( 'Verbindungsaufbau', $encoded );
	}

	/**
	 * Both host and port are required, and reported together when missing.
	 *
	 * @return void
	 */
	#[Test]
	public function requires_host_and_port(): void {
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) {
				TestCase::fail( 'fsockopen() must not be called without host and port.' );
			}
		);

		$test = new TcpConnect();
		$test->set_config( array() );
		$test->run();

		$result = $test->get_result();

		$this->assertSame( 'invalid_config', $result->get_error_code() );
		$this->assertSame( array( 'missing_config' => array( 'host', 'port' ) ), $result->get_data() );
	}

	/**
	 * The default timeout is applied when none is configured.
	 *
	 * @return void
	 */
	#[Test]
	public function defaults_to_an_eight_second_timeout(): void {
		$timeout_seen = null;

		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$timeout_seen ) {
				$timeout_seen = $timeout;

				return fopen( 'php://memory', 'rb' );
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host' => 'example.com',
				'port' => 80,
			)
		);
		$test->run();

		$this->assertSame( 8.0, $timeout_seen );
	}

	/**
	 * Without a target filter the host is handed to fsockopen() untouched,
	 * nothing is resolved up front.
	 *
	 * @return void
	 */
	#[Test]
	public function does_not_resolve_the_host_without_a_target_filter(): void {
		$this->fail_on_any_lookup();

		$host_seen = null;

		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$host_seen ) {
				$host_seen = $hostname;

				return fopen( 'php://memory', 'rb' );
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host' => 'example.com',
				'port' => 443,
			)
		);
		$test->run();

		$this->assertSame( 'example.com', $host_seen );
	}

	/**
	 * With a target filter the host is resolved once, the filter is asked,
	 * and the connection goes to exactly the IP it has accepted.
	 *
	 * @return void
	 */
	#[Test]
	public function connects_to_the_ip_the_filter_has_accepted(): void {
		$asked     = array();
		$host_seen = null;

		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): array => array( '93.184.216.34' ) );
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$host_seen ) {
				$host_seen = $hostname;

				return fopen( 'php://memory', 'rb' );
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'          => 'example.com',
				'port'          => 443,
				'target_filter' => static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
					$asked[] = array( $host, $ip, $port );

					return true;
				},
			)
		);
		$test->run();

		$result = $test->get_result();

		$this->assertSame( array( array( 'example.com', '93.184.216.34', 443 ) ), $asked );
		$this->assertSame( '93.184.216.34', $host_seen );
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame(
			array(
				'host' => 'example.com',
				'port' => 443,
			),
			$result->get_data()
		);
	}

	/**
	 * A rejected target is never connected to.
	 *
	 * @return void
	 */
	#[Test]
	public function does_not_connect_to_a_rejected_target(): void {
		$this->fail_on_any_connect();

		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): array => array( '10.0.0.5' ) );
		FunctionMocks::set_for_traits( 'dns_get_record', static fn( string $hostname, int $type ): array => array() );

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'          => 'intranet.example.com',
				'port'          => 3306,
				'target_filter' => Target_Filter::public_only(),
			)
		);
		$test->run();

		$result = $test->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'target_rejected', $result->get_error_code() );
		$this->assertNull( $result->get_value() );
		$this->assertNull( $result->get_duration_ms() );
		$this->assertSame(
			array(
				'host' => 'intranet.example.com',
				'port' => 3306,
			),
			$result->get_data()
		);
	}

	/**
	 * An IP address given as host is checked as well - without any lookup.
	 *
	 * @return void
	 */
	#[Test]
	public function checks_an_ip_address_given_as_host(): void {
		$this->fail_on_any_lookup();
		$this->fail_on_any_connect();

		foreach ( array( '127.0.0.1', '169.254.169.254', '100.64.0.1', '::1', '[::1]', '::ffff:127.0.0.1' ) as $host ) {
			$test = new TcpConnect();
			$test->set_config(
				array(
					'host'          => $host,
					'port'          => 80,
					'target_filter' => Target_Filter::public_only(),
				)
			);
			$test->run();

			$this->assertSame( 'target_rejected', $test->get_result()->get_error_code(), $host );
		}
	}

	/**
	 * A host without an accepted IPv4 address is connected to via IPv6,
	 * with the address in the bracket notation fsockopen() expects.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_back_to_an_ipv6_address(): void {
		$host_seen     = null;
		$types_queried = array();

		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): bool => false );
		FunctionMocks::set_for_traits(
			'dns_get_record',
			static function ( string $hostname, int $type ) use ( &$types_queried ): array {
				$types_queried[] = $type;

				return array(
					array(
						'host' => $hostname,
						'type' => 'AAAA',
						'ipv6' => '2606:4700:4700::1111',
					),
				);
			}
		);
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$host_seen ) {
				$host_seen = $hostname;

				return fopen( 'php://memory', 'rb' );
			}
		);

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'          => 'v6only.example.com',
				'port'          => 443,
				'target_filter' => Target_Filter::public_only(),
			)
		);
		$test->run();

		$this->assertSame( Status::SUCCESS, $test->get_result()->get_status() );
		$this->assertSame( '[2606:4700:4700::1111]', $host_seen );
		$this->assertSame( array( DNS_AAAA ), $types_queried );
	}

	/**
	 * A host that does not resolve is reported as such, not as rejected.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_host_that_does_not_resolve(): void {
		$this->fail_on_any_connect();

		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): bool => false );
		FunctionMocks::set_for_traits( 'dns_get_record', static fn( string $hostname, int $type ): bool => false );

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host'          => 'gone.example.com',
				'port'          => 443,
				'target_filter' => static fn( string $host, string $ip, ?int $port ): bool => true,
			)
		);
		$test->run();

		$this->assertSame( Status::ERROR, $test->get_result()->get_status() );
		$this->assertSame( 'dns_resolution_failed', $test->get_result()->get_error_code() );
	}

	/**
	 * With a filter, a host that is neither a plain name nor an IP address
	 * is refused without any lookup.
	 *
	 * @return void
	 */
	#[Test]
	public function refuses_an_unusual_host_with_a_target_filter(): void {
		$this->fail_on_any_lookup();
		$this->fail_on_any_connect();

		$hosts = array(
			'',
			'-x',
			'example.com/path',
			'ssl://example.com',
			'unix:///var/run/docker.sock',
			"example.com\n",
			// Other notations of 127.0.0.1 and 169.254.169.254: resolvers do not agree on what they mean.
			'2130706433',
			'127.1',
			'017700000001',
			'0x7f000001',
			'0x7f.1',
			'127.0x0.0.1',
			'0xa9fea9fe',
		);

		foreach ( $hosts as $host ) {
			$test = new TcpConnect();
			$test->set_config(
				array(
					'host'          => $host,
					'port'          => 443,
					'target_filter' => static fn( string $host, string $ip, ?int $port ): bool => true,
				)
			);
			$test->run();

			$this->assertSame( 'invalid_host', $test->get_result()->get_error_code(), (string) json_encode( $host ) );
		}
	}

	/**
	 * A port that is no TCP port is refused. fsockopen() would wrap it
	 * around and connect to a different port than the one reported - and
	 * than the one a target filter has been asked about.
	 *
	 * @return void
	 */
	#[Test]
	public function refuses_a_port_out_of_range(): void {
		$this->fail_on_any_lookup();
		$this->fail_on_any_connect();

		foreach ( array( 0, -1, 65536, 65616, 83617 ) as $port ) {
			foreach ( array( false, true ) as $with_filter ) {
				$config = array(
					'host' => 'example.com',
					'port' => $port,
				);

				if ( $with_filter ) {
					$config['target_filter'] = static function ( string $host, string $ip, ?int $port ): bool {
						TestCase::fail( 'The filter must not be asked about an invalid port.' );
					};
				}

				$test = new TcpConnect();
				$test->set_config( $config );
				$test->run();

				$this->assertSame( Status::ERROR, $test->get_result()->get_status(), (string) $port );
				$this->assertSame( 'invalid_port', $test->get_result()->get_error_code(), (string) $port );
				$this->assertSame(
					array(
						'host' => 'example.com',
						'port' => $port,
					),
					$test->get_result()->get_data()
				);
			}
		}
	}

	/**
	 * The first and the last TCP port are valid.
	 *
	 * @return void
	 */
	#[Test]
	public function accepts_the_first_and_the_last_port(): void {
		$ports_seen = array();

		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$ports_seen ) {
				$ports_seen[] = $port;

				return fopen( 'php://memory', 'rb' );
			}
		);

		foreach ( array( 1, 65535 ) as $port ) {
			$test = new TcpConnect();
			$test->set_config(
				array(
					'host' => 'example.com',
					'port' => $port,
				)
			);
			$test->run();

			$this->assertSame( Status::SUCCESS, $test->get_result()->get_status() );
		}

		$this->assertSame( array( 1, 65535 ), $ports_seen );
	}

	/**
	 * A timeout that is not positive is replaced by the default. Otherwise
	 * every failure would count as a timeout: the classification compares
	 * the elapsed time with the timeout.
	 *
	 * @return void
	 */
	#[Test]
	public function replaces_a_timeout_that_is_not_positive(): void {
		foreach ( array( 0, -5, 'abc', array( 3 ) ) as $timeout ) {
			$timeout_seen = null;

			FunctionMocks::set_for_tests(
				'fsockopen',
				static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) use ( &$timeout_seen ) {
					$timeout_seen = $timeout;
					$error_code   = 111;

					return false;
				}
			);

			$test = new TcpConnect();
			$test->set_config(
				array(
					'host'    => 'example.com',
					'port'    => 9,
					'timeout' => $timeout,
				)
			);
			$test->run();

			$this->assertSame( 8.0, $timeout_seen );
			$this->assertSame( 'tcp_connect_refused', $test->get_result()->get_error_code() );
		}
	}

	/**
	 * A host or port that is not a scalar is a configuration error.
	 *
	 * @return void
	 */
	#[Test]
	public function refuses_a_host_or_port_that_is_not_a_scalar(): void {
		$this->fail_on_any_connect();

		$test = new TcpConnect();
		$test->set_config(
			array(
				'host' => array( 'example.com' ),
				'port' => new \stdClass(),
			)
		);
		$test->run();

		$this->assertSame( 'invalid_config', $test->get_result()->get_error_code() );
		$this->assertSame( array( 'invalid_config' => array( 'host', 'port' ) ), $test->get_result()->get_data() );
	}

	/**
	 * Make every name resolution of the target guard fail the test.
	 *
	 * @return void
	 */
	private function fail_on_any_lookup(): void {
		FunctionMocks::set_for_traits(
			'gethostbynamel',
			static function ( string $hostname ): array {
				TestCase::fail( 'gethostbynamel() must not be called.' );
			}
		);
		FunctionMocks::set_for_traits(
			'dns_get_record',
			static function ( string $hostname, int $type ): array {
				TestCase::fail( 'dns_get_record() must not be called.' );
			}
		);
	}

	/**
	 * Make every connection attempt fail the test.
	 *
	 * @return void
	 */
	private function fail_on_any_connect(): void {
		FunctionMocks::set_for_tests(
			'fsockopen',
			static function ( string $hostname, int $port, int &$error_code, string &$error_message, ?float $timeout ) {
				TestCase::fail( 'fsockopen() must not be called, got ' . $hostname );
			}
		);
	}
}
