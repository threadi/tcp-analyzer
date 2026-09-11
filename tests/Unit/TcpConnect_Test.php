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
}
