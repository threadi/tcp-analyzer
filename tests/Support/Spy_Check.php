<?php
/**
 * File to hold a spying test double used by the TcpAnalyzer test case.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;

/**
 * Records how TcpAnalyzer instantiates and configures a test.
 *
 * TcpAnalyzer::run() creates the instances itself, so the recording has to
 * happen statically - there is no seam to inject a prepared object.
 */
class Spy_Check extends Tests_Base {

	/**
	 * Configs seen by execute(), slug => config.
	 *
	 * @var array<string,array<string,mixed>>
	 */
	public static array $configs = array();

	/**
	 * Number of instances created.
	 *
	 * @var int
	 */
	public static int $instances = 0;

	/**
	 * Constructor, counts instantiations.
	 */
	public function __construct() {
		++self::$instances;
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'spy';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function execute(): void {
		self::$configs[ $this->get_slug() ] = $this->config;

		$this->set_result( Status::SUCCESS, 'spy-value', array( 'slug' => $this->get_slug() ), null, 1.23 );
	}

	/**
	 * Reset the static recording between tests.
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$configs   = array();
		self::$instances = 0;
	}
}
