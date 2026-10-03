<?php
/**
 * File to test the traceroute test and its method chain.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\PHPUnitTests\Support\Fake_Method;
use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;
use TcpAnalyzer\Result;
use TcpAnalyzer\Target_Filter;
use TcpAnalyzer\Tests\Traceroute;
use TcpAnalyzer\Traceroute\Shell_Method;
use TcpAnalyzer\Traceroute\Socket_Method;

/**
 * Tests for TcpAnalyzer\Tests\Traceroute.
 *
 * Only the orchestration is under test here: which method is picked, what is
 * reported when none is available, and how the config reaches the method.
 * The methods themselves have their own test cases.
 */
#[CoversClass( Traceroute::class )]
final class Traceroute_Test extends TestCase {

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		FunctionMocks::reset();

		parent::tearDown();
	}

	/**
	 * A single hop, used as a canned method answer.
	 *
	 * @return array<int,array{hop:int,ip:?string,times_ms:float[]}>
	 */
	private static function hops(): array {
		return array(
			array(
				'hop'      => 1,
				'ip'       => '192.168.178.1',
				'times_ms' => array( 0.512 ),
			),
			array(
				'hop'      => 2,
				'ip'       => null,
				'times_ms' => array(),
			),
		);
	}

	/**
	 * The slug is part of the public contract.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_published_slug(): void {
		$this->assertSame( 'traceroute', ( new Traceroute() )->get_slug() );
	}

	/**
	 * Both built-in methods are registered out of the box.
	 *
	 * @return void
	 */
	#[Test]
	public function ships_the_built_in_methods(): void {
		$available = ( new Traceroute() )->get_available_methods();

		$this->assertSame( array( 'shell', 'socket' ), array_keys( $available ) );
		$this->assertInstanceOf( Shell_Method::class, $available['shell'] );
		$this->assertInstanceOf( Socket_Method::class, $available['socket'] );
	}

	/**
	 * A registered method replaces the built-in one with the same slug.
	 *
	 * @return void
	 */
	#[Test]
	public function overrides_a_built_in_method(): void {
		$test = new Traceroute();
		$fake = new Fake_Method( 'shell' );

		$test->register_method( $fake );

		$this->assertSame( $fake, $test->get_available_methods()['shell'] );
		$this->assertCount( 2, $test->get_available_methods() );
	}

	/**
	 * The first available method wins, and the rest is not consulted.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_first_available_method(): void {
		$first  = new Fake_Method( 'first', null, self::hops() );
		$second = new Fake_Method( 'second', null, self::hops() );

		$result = $this->run_with( array( $first, $second ), array( 'first', 'second' ) );

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertCount( 1, $first->calls );
		$this->assertSame( array(), $second->calls );
		$this->assertSame( 'first', $result->get_data()['method'] );
	}

	/**
	 * The configured order decides, not the registration order.
	 *
	 * @return void
	 */
	#[Test]
	public function follows_the_configured_order(): void {
		$first  = new Fake_Method( 'first', null, self::hops() );
		$second = new Fake_Method( 'second', null, self::hops() );

		$result = $this->run_with( array( $first, $second ), array( 'second', 'first' ) );

		$this->assertSame( 'second', $result->get_data()['method'] );
		$this->assertSame( array(), $first->calls );
	}

	/**
	 * An unavailable method is skipped without being run.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_through_to_the_next_available_method(): void {
		$unavailable = new Fake_Method( 'shell', 'shell_exec_disabled', self::hops() );
		$available   = new Fake_Method( 'socket', null, self::hops() );

		$result = $this->run_with( array( $unavailable, $available ), array( 'shell', 'socket' ) );

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( array(), $unavailable->calls );
		$this->assertCount( 1, $available->calls );
		$this->assertSame( 'socket', $result->get_data()['method'] );
	}

	/**
	 * A method that is available but yields nothing is not a zero-hop
	 * success - the chain continues.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_through_when_a_method_yields_no_hops(): void {
		$empty     = new Fake_Method( 'shell', null, array() );
		$succeeded = new Fake_Method( 'socket', null, self::hops() );

		$result = $this->run_with( array( $empty, $succeeded ), array( 'shell', 'socket' ) );

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertCount( 1, $empty->calls );
		$this->assertSame( 'socket', $result->get_data()['method'] );
	}

	/**
	 * On success the hops are the result value, and the data says which
	 * method produced them.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_hops_and_the_method_used(): void {
		$result = $this->run_with( array( new Fake_Method( 'socket', null, self::hops() ) ), array( 'socket' ) );

		$this->assertSame( self::hops(), $result->get_value() );
		$this->assertNull( $result->get_error_code() );
		$this->assertIsFloat( $result->get_duration_ms() );
		$this->assertSame(
			array(
				'host'      => 'example.com',
				'hop_count' => 2,
				'method'    => 'socket',
			),
			$result->get_data()
		);
	}

	/**
	 * Host and limits are handed to the method unchanged.
	 *
	 * @return void
	 */
	#[Test]
	public function passes_the_config_to_the_method(): void {
		$method = new Fake_Method( 'socket', null, self::hops() );

		$this->run_with(
			array( $method ),
			array( 'socket' ),
			array(
				'max_hops' => 5,
				'wait'     => 1,
			)
		);

		$this->assertSame(
			array(
				'host'     => 'example.com',
				'max_hops' => 5,
				'wait'     => 1,
			),
			$method->calls[0]
		);
	}

	/**
	 * The documented defaults are applied.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_default_hop_limit_and_wait_time(): void {
		$method = new Fake_Method( 'socket', null, self::hops() );

		$this->run_with( array( $method ), array( 'socket' ) );

		$this->assertSame( 20, $method->calls[0]['max_hops'] );
		$this->assertSame( 2, $method->calls[0]['wait'] );
	}

	/**
	 * Without an explicit config, shell is tried before socket.
	 *
	 * @return void
	 */
	#[Test]
	public function tries_shell_before_socket_by_default(): void {
		$shell  = new Fake_Method( 'shell', null, self::hops() );
		$socket = new Fake_Method( 'socket', null, self::hops() );

		$test = new Traceroute();
		$test->register_method( $shell );
		$test->register_method( $socket );
		$test->set_config( array( 'host' => 'example.com' ) );
		$test->run();

		$this->assertSame( 'shell', $test->get_result()->get_data()['method'] );
		$this->assertSame( array(), $socket->calls );
	}

	/**
	 * If no method can run, the test is skipped - not failed - and the
	 * reason per method is reported so the consuming project can explain it.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_with_a_reason_per_method(): void {
		$result = $this->run_with(
			array(
				new Fake_Method( 'shell', 'shell_exec_disabled' ),
				new Fake_Method( 'socket', 'raw_socket_denied' ),
			),
			array( 'shell', 'socket' )
		);

		$this->assertSame( Status::SKIPPED, $result->get_status() );
		$this->assertSame( 'traceroute_unavailable', $result->get_error_code() );
		$this->assertNull( $result->get_value() );
		$this->assertSame(
			array(
				'host'    => 'example.com',
				'methods' => array(
					'shell'  => 'shell_exec_disabled',
					'socket' => 'raw_socket_denied',
				),
			),
			$result->get_data()
		);
	}

	/**
	 * A method that ran but produced nothing is reported with its own
	 * reason, distinct from "was never available".
	 *
	 * @return void
	 */
	#[Test]
	public function distinguishes_an_empty_run_from_an_unavailable_method(): void {
		$result = $this->run_with(
			array(
				new Fake_Method( 'shell', null, array() ),
				new Fake_Method( 'socket', 'sockets_unavailable' ),
			),
			array( 'shell', 'socket' )
		);

		$this->assertSame(
			array(
				'shell'  => 'traceroute_unavailable',
				'socket' => 'sockets_unavailable',
			),
			$result->get_data()['methods']
		);
	}

	/**
	 * Nothing was executed, so there is no runtime to report.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_no_duration_when_nothing_ran(): void {
		$result = $this->run_with( array( new Fake_Method( 'shell', 'shell_exec_unavailable' ) ), array( 'shell' ) );

		$this->assertNull( $result->get_duration_ms() );
	}

	/**
	 * A method that ran without success still took time, and that is
	 * reported.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_duration_when_a_method_ran(): void {
		$result = $this->run_with( array( new Fake_Method( 'shell', null, array() ) ), array( 'shell' ) );

		$this->assertIsFloat( $result->get_duration_ms() );
	}

	/**
	 * A configured slug without a registered method does not blow up.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_an_unknown_method_slug(): void {
		$result = $this->run_with( array(), array( 'does_not_exist' ) );

		$this->assertSame( Status::SKIPPED, $result->get_status() );
		$this->assertSame( array( 'does_not_exist' => 'unknown_method' ), $result->get_data()['methods'] );
	}

	/**
	 * An empty method list is a valid, if useless, configuration.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_without_any_configured_method(): void {
		$result = $this->run_with( array( new Fake_Method( 'shell', null, self::hops() ) ), array() );

		$this->assertSame( Status::SKIPPED, $result->get_status() );
		$this->assertSame( array(), $result->get_data()['methods'] );
	}

	/**
	 * Without a host no method is consulted at all.
	 *
	 * @return void
	 */
	#[Test]
	public function requires_a_host(): void {
		$method = new Fake_Method( 'shell', null, self::hops() );

		$test = new Traceroute();
		$test->register_method( $method );
		$test->set_config( array( 'methods' => array( 'shell' ) ) );
		$test->run();

		$result = $test->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'invalid_config', $result->get_error_code() );
		$this->assertSame( array(), $method->calls );
	}

	/**
	 * A host that is neither a plain name nor an IP address is an error, no
	 * method is consulted.
	 *
	 * @return void
	 */
	#[Test]
	public function refuses_a_host_that_is_not_plain(): void {
		foreach ( array( '-i', '--help', 'example.com; id', "example.com\n-i", '' ) as $host ) {
			$method = new Fake_Method( 'shell', null, self::hops() );
			$result = $this->run_with( array( $method ), array( 'shell' ), array( 'host' => $host ) );

			$this->assertSame( Status::ERROR, $result->get_status(), (string) json_encode( $host ) );
			$this->assertSame( 'invalid_host', $result->get_error_code(), (string) json_encode( $host ) );
			$this->assertSame( array( 'host' => $host ), $result->get_data() );
			$this->assertNull( $result->get_duration_ms() );
			$this->assertSame( array(), $method->calls );
		}
	}

	/**
	 * The number of hops and the wait time are kept within limits, whatever
	 * is configured: both multiply into the runtime of a trace.
	 *
	 * @return void
	 */
	#[Test]
	public function limits_the_hops_and_the_wait_time(): void {
		$cases = array(
			array( 300, 100, 64, 10 ),
			array( 0, 0, 1, 1 ),
			array( -5, -5, 1, 1 ),
			array( 64, 10, 64, 10 ),
			array( '12', '3', 12, 3 ),
			array( array( 5 ), new \stdClass(), 20, 2 ),
		);

		foreach ( $cases as $case ) {
			$method = new Fake_Method( 'shell', null, self::hops() );

			$this->run_with(
				array( $method ),
				array( 'shell' ),
				array(
					'max_hops' => $case[0],
					'wait'     => $case[1],
				)
			);

			$this->assertSame( $case[2], $method->calls[0]['max_hops'] );
			$this->assertSame( $case[3], $method->calls[0]['wait'] );
		}
	}

	/**
	 * Anything but a slug in the method list is skipped, without a PHP warning.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_methods_that_are_not_strings(): void {
		$method = new Fake_Method( 'shell', null, self::hops() );
		$result = $this->run_with( array( $method ), array( array( 'shell' ), null, 42, 'shell' ) );

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertCount( 1, $method->calls );
	}

	/**
	 * An IPv6 address in brackets reaches the method without them.
	 *
	 * @return void
	 */
	#[Test]
	public function hands_a_bracketed_ipv6_address_over_without_brackets(): void {
		$method = new Fake_Method( 'shell', null, self::hops() );
		$result = $this->run_with( array( $method ), array( 'shell' ), array( 'host' => '[2001:db8::1]' ) );

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( '2001:db8::1', $method->calls[0]['host'] );
		$this->assertSame( '[2001:db8::1]', $result->get_data()['host'] );
	}

	/**
	 * With a target filter the method traces the IP the filter has
	 * accepted, while the result still names the configured host.
	 *
	 * @return void
	 */
	#[Test]
	public function traces_the_ip_the_filter_has_accepted(): void {
		$asked = array();

		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): array => array( '93.184.216.34' ) );

		$method = new Fake_Method( 'shell', null, self::hops() );
		$result = $this->run_with(
			array( $method ),
			array( 'shell' ),
			array(
				'target_filter' => static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
					$asked[] = array( $host, $ip, $port );

					return true;
				},
			)
		);

		$this->assertSame( array( array( 'example.com', '93.184.216.34', null ) ), $asked );
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( '93.184.216.34', $method->calls[0]['host'] );
		$this->assertSame( 'example.com', $result->get_data()['host'] );
	}

	/**
	 * A rejected target is not traced.
	 *
	 * @return void
	 */
	#[Test]
	public function does_not_trace_a_rejected_target(): void {
		FunctionMocks::set_for_traits( 'gethostbynamel', static fn( string $hostname ): array => array( '192.168.1.1' ) );
		FunctionMocks::set_for_traits( 'dns_get_record', static fn( string $hostname, int $type ): array => array() );

		$method = new Fake_Method( 'shell', null, self::hops() );
		$result = $this->run_with( array( $method ), array( 'shell' ), array( 'target_filter' => Target_Filter::public_only() ) );

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'target_rejected', $result->get_error_code() );
		$this->assertSame( array( 'host' => 'example.com' ), $result->get_data() );
		$this->assertSame( array(), $method->calls );
	}

	/**
	 * Run the traceroute test with the given methods and config.
	 *
	 * @param Fake_Method[]       $methods Methods to register.
	 * @param string[]            $order   Method slugs to configure.
	 * @param array<string,mixed> $config  Additional configuration.
	 * @return Result
	 */
	private function run_with( array $methods, array $order, array $config = array() ): Result {
		$test = new Traceroute();

		foreach ( $methods as $method ) {
			$test->register_method( $method );
		}

		$test->set_config(
			array_merge(
				array(
					'host'    => 'example.com',
					'methods' => $order,
				),
				$config
			)
		);
		$test->run();

		return $test->get_result();
	}
}
