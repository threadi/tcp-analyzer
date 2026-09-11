<?php
/**
 * File to test the DNS resolution test.
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
use TcpAnalyzer\Tests\Dns;

/**
 * Tests for TcpAnalyzer\Tests\Dns.
 *
 * gethostbyname() is stubbed in the TcpAnalyzer\Tests namespace, so these
 * tests never hit a resolver and stay deterministic on any machine.
 */
#[CoversClass( Dns::class )]
final class Dns_Test extends TestCase {

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
		$this->assertSame( 'dns', ( new Dns() )->get_slug() );
	}

	/**
	 * A resolved hostname is reported as the result value.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_resolved_ip(): void {
		$seen = array();

		FunctionMocks::set_for_tests(
			'gethostbyname',
			static function ( string $hostname ) use ( &$seen ): string {
				$seen[] = $hostname;

				return '93.184.216.34';
			}
		);

		$dns = new Dns();
		$dns->set_config( array( 'host' => 'example.com' ) );
		$dns->run();

		$result = $dns->get_result();

		$this->assertSame( array( 'example.com' ), $seen );
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( '93.184.216.34', $result->get_value() );
		$this->assertSame( array( 'host' => 'example.com' ), $result->get_data() );
		$this->assertNull( $result->get_error_code() );
		$this->assertIsFloat( $result->get_duration_ms() );
	}

	/**
	 * gethostbyname() returns the input unchanged when resolution fails -
	 * that is the failure signal the test has to detect.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_failed_resolution(): void {
		FunctionMocks::set_for_tests(
			'gethostbyname',
			static fn( string $hostname ): string => $hostname
		);

		$dns = new Dns();
		$dns->set_config( array( 'host' => 'does-not-exist.invalid' ) );
		$dns->run();

		$result = $dns->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertNull( $result->get_value() );
		$this->assertSame( 'dns_resolution_failed', $result->get_error_code() );
		$this->assertSame( array( 'host' => 'does-not-exist.invalid' ), $result->get_data() );
		$this->assertIsFloat( $result->get_duration_ms() );
	}

	/**
	 * Resolving a host to itself is only a failure for hostnames: an IP
	 * address passed in resolves to itself and is still reported as an error
	 * by the current implementation. Pinned as known behaviour.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_an_ip_input_as_failed_resolution(): void {
		FunctionMocks::set_for_tests(
			'gethostbyname',
			static fn( string $hostname ): string => $hostname
		);

		$dns = new Dns();
		$dns->set_config( array( 'host' => '93.184.216.34' ) );
		$dns->run();

		$this->assertSame( 'dns_resolution_failed', $dns->get_result()->get_error_code() );
	}

	/**
	 * Without a host the test never touches the resolver.
	 *
	 * @return void
	 */
	#[Test]
	public function requires_a_host(): void {
		FunctionMocks::set_for_tests(
			'gethostbyname',
			static function ( string $hostname ): string {
				TestCase::fail( 'gethostbyname() must not be called without a configured host.' );
			}
		);

		$dns = new Dns();
		$dns->set_config( array() );
		$dns->run();

		$result = $dns->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'invalid_config', $result->get_error_code() );
		$this->assertSame( array( 'missing_config' => array( 'host' ) ), $result->get_data() );
	}
}
