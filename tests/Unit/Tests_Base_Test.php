<?php
/**
 * File to test the abstract base object for tests.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\PHPUnitTests\Support\Configurable_Check;
use TcpAnalyzer\Result;
use TcpAnalyzer\Test_Interface;
use TcpAnalyzer\Tests_Base;

/**
 * Tests for TcpAnalyzer\Tests_Base, exercised through a concrete fixture.
 */
#[CoversClass( Tests_Base::class )]
final class Tests_Base_Test extends TestCase {

	/**
	 * The fixture under test.
	 *
	 * @var Configurable_Check
	 */
	private Configurable_Check $check;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->check = new Configurable_Check();
	}

	/**
	 * The base class satisfies the published interface.
	 *
	 * @return void
	 */
	#[Test]
	public function implements_the_test_interface(): void {
		$this->assertInstanceOf( Test_Interface::class, $this->check );
	}

	/**
	 * set_config() merges on top of the defaults instead of replacing them.
	 *
	 * @return void
	 */
	#[Test]
	public function merges_given_config_into_the_defaults(): void {
		$this->check->set_config( array( 'mode' => 'custom' ) );

		$this->assertSame(
			array(
				'timeout' => 5,
				'mode'    => 'custom',
			),
			$this->check->read_all_config()
		);
	}

	/**
	 * Unknown keys are kept, so tests can accept additional options.
	 *
	 * @return void
	 */
	#[Test]
	public function keeps_unknown_config_keys(): void {
		$this->check->set_config( array( 'extra' => 'kept' ) );

		$this->assertSame( 'kept', $this->check->read_config( 'extra' ) );
	}

	/**
	 * get_config() falls back to the given default for unknown keys.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_back_to_the_given_default(): void {
		$this->check->set_config( array() );

		$this->assertNull( $this->check->read_config( 'missing' ) );
		$this->assertSame( 'fallback', $this->check->read_config( 'missing', 'fallback' ) );
		$this->assertSame( 5, $this->check->read_config( 'timeout', 99 ) );
	}

	/**
	 * get_config() uses the null coalescing operator, so an explicitly
	 * configured null is indistinguishable from a missing key and yields the
	 * default. run() on the other hand does distinguish the two (see below).
	 *
	 * @return void
	 */
	#[Test]
	public function returns_the_default_for_an_explicit_null_value(): void {
		$this->check->set_config( array( 'mode' => null ) );

		$this->assertSame( 'fallback', $this->check->read_config( 'mode', 'fallback' ) );
	}

	/**
	 * With all required keys present, execute() runs and stores the result.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_execute_when_the_required_config_is_present(): void {
		$this->check->required = array( 'mode' );
		$this->check->set_config( array( 'mode' => 'custom' ) );
		$this->check->run();

		$result = $this->check->get_result();

		$this->assertTrue( $this->check->executed );
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( 'configurable_check', $result->get_slug() );
		$this->assertSame( 'measured-value', $result->get_value() );
		$this->assertNull( $result->get_error_code() );
	}

	/**
	 * Missing required keys short-circuit the run with a structured error,
	 * without ever entering execute().
	 *
	 * @return void
	 */
	#[Test]
	public function short_circuits_on_missing_required_config(): void {
		$this->check->required = array( 'host', 'port' );
		$this->check->set_config( array( 'host' => 'example.com' ) );
		$this->check->run();

		$result = $this->check->get_result();

		$this->assertFalse( $this->check->executed );
		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'invalid_config', $result->get_error_code() );
		$this->assertNull( $result->get_value() );
		$this->assertNull( $result->get_duration_ms() );
		$this->assertSame( array( 'missing_config' => array( 'port' ) ), $result->get_data() );
	}

	/**
	 * A required key that is present but null counts as missing.
	 *
	 * @return void
	 */
	#[Test]
	public function treats_a_null_required_value_as_missing(): void {
		$this->check->required = array( 'host' );
		$this->check->set_config( array( 'host' => null ) );
		$this->check->run();

		$this->assertSame( 'invalid_config', $this->check->get_result()->get_error_code() );
		$this->assertSame( array( 'missing_config' => array( 'host' ) ), $this->check->get_result()->get_data() );
	}

	/**
	 * The missing keys are reported as a list, not with holes in the index.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_missing_keys_as_a_list(): void {
		$this->check->required = array( 'host', 'port', 'scheme' );
		$this->check->set_config( array( 'port' => 443 ) );
		$this->check->run();

		/**
		 * The reported missing keys.
		 *
		 * @var array<string,mixed> $data
		 */
		$data = $this->check->get_result()->get_data();

		$this->assertSame( array( 'host', 'scheme' ), $data['missing_config'] );
		$this->assertSame( array( 0, 1 ), array_keys( $data['missing_config'] ) );
	}

	/**
	 * Defaults are applied by set_config(), so running a test without calling
	 * set_config() first leaves the config empty.
	 *
	 * @return void
	 */
	#[Test]
	public function does_not_apply_defaults_without_set_config(): void {
		$this->check->required = array( 'timeout' );
		$this->check->run();

		$this->assertFalse( $this->check->executed );
		$this->assertSame( 'invalid_config', $this->check->get_result()->get_error_code() );
	}

	/**
	 * Without required keys, a test runs even if set_config() was skipped.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_without_any_config_when_nothing_is_required(): void {
		$this->check->run();

		$this->assertTrue( $this->check->executed );
		$this->assertSame( array(), $this->check->seen_config );
	}

	/**
	 * The timer helpers produce a plausible, positive duration in ms.
	 *
	 * @return void
	 */
	#[Test]
	public function measures_the_duration_in_milliseconds(): void {
		$this->check->sleep_us = 20000;
		$this->check->run();

		$duration = $this->check->get_result()->get_duration_ms();

		$this->assertIsFloat( $duration );
		$this->assertGreaterThanOrEqual( 15.0, $duration );
		$this->assertLessThan( 5000.0, $duration );
		$this->assertSame( round( $duration, 2 ), $duration );
	}

	/**
	 * set_result() defaults to an empty, error-code-free result.
	 *
	 * @return void
	 */
	#[Test]
	public function stores_a_result_with_sensible_defaults(): void {
		$this->check->store_bare_result( Status::SKIPPED );

		$result = $this->check->get_result();

		$this->assertSame( Status::SKIPPED, $result->get_status() );
		$this->assertNull( $result->get_value() );
		$this->assertSame( array(), $result->get_data() );
		$this->assertNull( $result->get_error_code() );
		$this->assertNull( $result->get_duration_ms() );
	}

	/**
	 * Asking for a result before the test ran is a programming error.
	 *
	 * @return void
	 */
	#[Test]
	public function throws_when_the_result_is_requested_before_running(): void {
		$this->expectException( RuntimeException::class );
		$this->expectExceptionMessage( 'Test "configurable_check" has not been run yet.' );

		$this->check->get_result();
	}

	/**
	 * A second run replaces the previous result instead of appending.
	 *
	 * @return void
	 */
	#[Test]
	public function replaces_the_result_on_a_second_run(): void {
		$this->check->run();
		$first = $this->check->get_result();

		$this->check->result_status = Status::WARNING;
		$this->check->run();
		$second = $this->check->get_result();

		$this->assertInstanceOf( Result::class, $first );
		$this->assertNotSame( $first, $second );
		$this->assertSame( Status::WARNING, $second->get_status() );
	}
}
