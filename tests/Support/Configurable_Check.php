<?php
/**
 * File to hold a configurable test double for Tests_Base.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;

/**
 * A minimal concrete Tests_Base implementation used to exercise the base
 * class in isolation: defaults, required config, timing and result storage.
 */
final class Configurable_Check extends Tests_Base {

	/**
	 * Config keys reported as required.
	 *
	 * @var string[]
	 */
	public array $required = array();

	/**
	 * Default config reported by get_default_config().
	 *
	 * @var array<string,mixed>
	 */
	public array $defaults = array(
		'timeout' => 5,
		'mode'    => 'default',
	);

	/**
	 * Whether execute() has been called.
	 *
	 * @var bool
	 */
	public bool $executed = false;

	/**
	 * The config execute() has seen.
	 *
	 * @var array<string,mixed>
	 */
	public array $seen_config = array();

	/**
	 * Status execute() will report.
	 *
	 * @var Status
	 */
	public Status $result_status = Status::SUCCESS;

	/**
	 * Microseconds execute() sleeps, to produce a measurable duration.
	 *
	 * @var int
	 */
	public int $sleep_us = 1000;

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'configurable_check';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_default_config(): array {
		return $this->defaults;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_required_config(): array {
		return $this->required;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function execute(): void {
		$this->executed    = true;
		$this->seen_config = $this->config;

		$this->start_timer();
		usleep( $this->sleep_us );

		$this->set_result( $this->result_status, 'measured-value', array( 'context' => 'structured' ), null, $this->stop_timer() );
	}

	/**
	 * Expose the protected get_config() helper to the test case.
	 *
	 * @param string $key     Config key.
	 * @param mixed  $default Fallback value.
	 * @return mixed
	 */
	public function read_config( string $key, mixed $default = null ): mixed {
		return $this->get_config( $key, $default );
	}

	/**
	 * Expose the resolved config to the test case.
	 *
	 * @return array<string,mixed>
	 */
	public function read_all_config(): array {
		return $this->config;
	}

	/**
	 * Store a result without running the test, to check set_result() defaults.
	 *
	 * @param Status $status The status to store.
	 * @return void
	 */
	public function store_bare_result( Status $status ): void {
		$this->set_result( $status );
	}
}
