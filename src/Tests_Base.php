<?php
/**
 * File to handle the base object for any test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer;

use RuntimeException;
use TcpAnalyzer\Enums\Status;

/**
 * The base object for any test.
 *
 * Provides configuration handling, required-config validation, simple
 * timing helpers and result storage. Concrete tests only implement
 * get_slug(), optionally get_default_config()/get_required_config(),
 * and execute().
 */
abstract class Tests_Base implements Test_Interface {

	/**
	 * The resolved configuration for this run (defaults merged with given config).
	 *
	 * @var array<string,mixed>
	 */
	protected array $config = array();

	/**
	 * The result of the last run() call.
	 *
	 * @var Result|null
	 */
	private ?Result $result = null;

	/**
	 * Internal timer start, set via start_timer().
	 *
	 * @var float
	 */
	private float $timer_start = 0.0;

	/**
	 * {@inheritDoc}
	 */
	public function set_config( array $config ): void {
		$this->config = array_merge( $this->get_default_config(), $config );
	}

	/**
	 * Default configuration for this test, used as base before set_config() merges in overrides.
	 *
	 * @return array<string,mixed>
	 */
	protected function get_default_config(): array {
		return array();
	}

	/**
	 * Config keys that must be present and non-null before execute() may run.
	 *
	 * If any are missing, run() will short-circuit with an "invalid_config" error
	 * result and execute() is never called.
	 *
	 * @return string[]
	 */
	protected function get_required_config(): array {
		return array();
	}

	/**
	 * Read a single config value.
	 *
	 * @param string $key     Config key.
	 * @param mixed  $default Fallback value if not set.
	 * @return mixed
	 */
	protected function get_config( string $key, mixed $default = null ): mixed {
		return $this->config[ $key ] ?? $default;
	}

	/**
	 * Start the internal timer.
	 *
	 * @return void
	 */
	protected function start_timer(): void {
		$this->timer_start = microtime( true );
	}

	/**
	 * Stop the internal timer and return the elapsed time.
	 *
	 * @return float Elapsed time in milliseconds, rounded to 2 decimals.
	 */
	protected function stop_timer(): float {
		return round( ( microtime( true ) - $this->timer_start ) * 1000, 2 );
	}

	/**
	 * Store the result of this test run.
	 *
	 * @param Status      $status      The resulting status.
	 * @param mixed       $value       The primary, requested value of the test.
	 * @param array<string,mixed>       $data        Additional structured context data (no free text).
	 * @param string|null $error_code  Machine-readable error identifier, if status is not SUCCESS.
	 * @param float|null  $duration_ms Runtime of the test in milliseconds, if measured.
	 * @return void
	 */
	protected function set_result( Status $status, mixed $value = null, array $data = array(), ?string $error_code = null, ?float $duration_ms = null ): void {
		$this->result = new Result( $this->get_slug(), $status, $value, $data, $error_code, $duration_ms );
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_result(): Result {
		if ( null === $this->result ) {
			throw new RuntimeException( sprintf( 'Test "%s" has not been run yet.', $this->get_slug() ) );
		}

		return $this->result;
	}

	/**
	 * {@inheritDoc}
	 */
	public function run(): void {
		$missing = array_values(
			array_filter(
				$this->get_required_config(),
				fn( string $key ): bool => ! array_key_exists( $key, $this->config ) || null === $this->config[ $key ]
			)
		);

		if ( ! empty( $missing ) ) {
			$this->set_result( Status::ERROR, null, array( 'missing_config' => $missing ), 'invalid_config' );
			return;
		}

		$this->execute();
	}

	/**
	 * Run the actual test logic. Called by run() once required config is present.
	 *
	 * Implementations must call set_result() before returning.
	 *
	 * @return void
	 */
	abstract protected function execute(): void;
}
