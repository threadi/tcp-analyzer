<?php
/**
 * File to test the shell based traceroute method.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
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
	 * A host containing shell metacharacters must end up quoted, not
	 * executed.
	 *
	 * @return void
	 */
	#[Test]
	public function escapes_a_host_containing_shell_metacharacters(): void {
		$command_seen = null;

		FunctionMocks::set_for_traceroute(
			'shell_exec',
			static function ( string $command ) use ( &$command_seen ): string {
				$command_seen = $command;

				return self::SAMPLE_OUTPUT;
			}
		);

		$this->method->trace( 'example.com; id', 20, 2 );

		$this->assertSame( "traceroute -n -w 2 -m 20 'example.com; id' 2>&1", $command_seen );
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
