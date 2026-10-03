<?php
/**
 * File to test the shell based traceroute method.
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
use TcpAnalyzer\Traceroute\Shell_Method;

/**
 * Tests for TcpAnalyzer\Traceroute\Shell_Method.
 *
 * function_exists(), ini_get() and shell_exec() are stubbed in the
 * TcpAnalyzer\Traceroute namespace, so no command is ever executed.
 */
#[CoversClass( Shell_Method::class )]
final class Shell_Method_Test extends TestCase {

	/**
	 * Realistic traceroute output, including an unreachable hop.
	 *
	 * @var string
	 */
	private const SAMPLE_OUTPUT = "traceroute to example.com (93.184.216.34), 20 hops max, 60 byte packets\n 1  192.168.178.1  0.512 ms  0.480 ms  0.470 ms\n 2  * * *\n 3  62.155.246.10  12.345 ms  11.987 ms  12.100 ms\n";

	/**
	 * The method under test.
	 *
	 * @var Shell_Method
	 */
	private Shell_Method $method;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->method = new Shell_Method();

		// Default: shell_exec() exists and is not disabled.
		FunctionMocks::set_for_traceroute( 'function_exists', static fn( string $function ): bool => true );
		FunctionMocks::set_for_traceroute( 'ini_get', static fn( string $option ): string => '' );
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
		$this->assertSame( 'shell', $this->method->get_slug() );
	}

	/**
	 * With shell_exec() usable, the method reports itself as available.
	 *
	 * @return void
	 */
	#[Test]
	public function is_available_when_shell_exec_is_usable(): void {
		$this->assertNull( $this->method->check_availability() );
	}

	/**
	 * A missing shell_exec() is reported with its own code.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_missing_shell_exec(): void {
		FunctionMocks::set_for_traceroute( 'function_exists', static fn( string $function ): bool => 'shell_exec' !== $function );

		$this->assertSame( 'shell_exec_unavailable', $this->method->check_availability() );
	}

	/**
	 * A shell_exec() in disable_functions is reported separately, also when
	 * the list contains whitespace.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_disabled_shell_exec(): void {
		FunctionMocks::set_for_traceroute( 'ini_get', static fn( string $option ): string => 'exec, shell_exec ,passthru' );

		$this->assertSame( 'shell_exec_disabled', $this->method->check_availability() );
	}

	/**
	 * Other disabled functions do not block the method.
	 *
	 * @return void
	 */
	#[Test]
	public function ignores_other_disabled_functions(): void {
		FunctionMocks::set_for_traceroute( 'ini_get', static fn( string $option ): string => 'exec,passthru,proc_open' );

		$this->assertNull( $this->method->check_availability() );
	}

	/**
	 * Raw output is turned into purely numeric hop data.
	 *
	 * @return void
	 */
	#[Test]
	public function parses_the_output_into_structured_hops(): void {
		FunctionMocks::set_for_traceroute( 'shell_exec', static fn( string $command ): string => self::SAMPLE_OUTPUT );

		$this->assertSame(
			array(
				array(
					'hop'      => 1,
					'ip'       => '192.168.178.1',
					'times_ms' => array( 0.512, 0.48, 0.47 ),
				),
				array(
					'hop'      => 2,
					'ip'       => null,
					'times_ms' => array(),
				),
				array(
					'hop'      => 3,
					'ip'       => '62.155.246.10',
					'times_ms' => array( 12.345, 11.987, 12.1 ),
				),
			),
			$this->method->trace( 'example.com', 20, 2 )
		);
	}

	/**
	 * The command is built from the given arguments.
	 *
	 * @return void
	 */
	#[Test]
	public function builds_the_command_from_its_arguments(): void {
		$command_seen = null;

		FunctionMocks::set_for_traceroute(
			'shell_exec',
			static function ( string $command ) use ( &$command_seen ): string {
				$command_seen = $command;

				return self::SAMPLE_OUTPUT;
			}
		);

		$this->method->trace( 'example.com', 5, 1 );

		$this->assertSame( "traceroute -n -w 1 -m 5 'example.com' 2>&1", $command_seen );
	}

	/**
	 * Hops and wait time are brought into the range the binary accepts.
	 *
	 * @return void
	 */
	#[Test]
	public function keeps_hops_and_wait_time_in_range(): void {
		$commands_seen = array();

		FunctionMocks::set_for_traceroute(
			'shell_exec',
			static function ( string $command ) use ( &$commands_seen ): string {
				$commands_seen[] = $command;

				return self::SAMPLE_OUTPUT;
			}
		);

		$this->method->trace( 'example.com', 1000, 0 );
		$this->method->trace( 'example.com', -1, -1 );

		$this->assertSame(
			array(
				"traceroute -n -w 1 -m 255 'example.com' 2>&1",
				"traceroute -n -w 1 -m 1 'example.com' 2>&1",
			),
			$commands_seen
		);
	}

	/**
	 * An IP address is a valid host as well.
	 *
	 * @return void
	 */
	#[Test]
	public function accepts_an_ip_address_as_host(): void {
		$commands_seen = array();

		FunctionMocks::set_for_traceroute(
			'shell_exec',
			static function ( string $command ) use ( &$commands_seen ): string {
				$commands_seen[] = $command;

				return self::SAMPLE_OUTPUT;
			}
		);

		$this->method->trace( '93.184.216.34', 20, 2 );
		$this->method->trace( '2001:db8::1', 20, 2 );

		$this->assertSame(
			array(
				"traceroute -n -w 2 -m 20 '93.184.216.34' 2>&1",
				"traceroute -n -w 2 -m 20 '2001:db8::1' 2>&1",
			),
			$commands_seen
		);
	}

	/**
	 * Only a plain hostname or IP address reaches the command line.
	 *
	 * Quoting alone is not enough: a host starting with a dash stays inside
	 * its quotes, but traceroute would still read it as an option.
	 *
	 * @param string $host The host to trace.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_hosts_that_are_not_plain' )]
	public function never_runs_a_command_for_a_host_that_is_not_plain( string $host ): void {
		FunctionMocks::set_for_traceroute(
			'shell_exec',
			static function ( string $command ): string {
				TestCase::fail( 'shell_exec() must not be called: ' . $command );
			}
		);

		$this->assertSame( array(), $this->method->trace( $host, 20, 2 ) );
	}

	/**
	 * Data provider: hosts that must never reach the command line.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_hosts_that_are_not_plain(): array {
		return array(
			'short option'          => array( '-i' ),
			'long option'           => array( '--help' ),
			'option with value'     => array( '-g10.0.0.1' ),
			'shell metacharacters'  => array( 'example.com; id' ),
			'command substitution'  => array( '$(id)' ),
			'second line'           => array( "example.com\n-i" ),
			'trailing line break'   => array( "example.com\n" ),
			'whitespace'            => array( 'example.com -i' ),
			'quote'                 => array( "example.com'" ),
			'empty'                 => array( '' ),
		);
	}

	/**
	 * No output means the binary is missing or not permitted.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_nothing_on_empty_output(): void {
		FunctionMocks::set_for_traceroute( 'shell_exec', static fn( string $command ): ?string => null );

		$this->assertSame( array(), $this->method->trace( 'example.com', 20, 2 ) );
	}

	/**
	 * Output without a parsable hop is not a zero-hop success.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_nothing_on_output_without_hops(): void {
		FunctionMocks::set_for_traceroute( 'shell_exec', static fn( string $command ): string => "sh: 1: traceroute: not found\n" );

		$this->assertSame( array(), $this->method->trace( 'example.com', 20, 2 ) );
	}
}
