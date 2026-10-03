<?php
/**
 * File to define the interface any test must implement.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer;

/**
 * Interface any test class must implement.
 *
 * Implement this directly only if a test cannot extend Tests_Base for
 * some reason - normally extend Tests_Base instead, it already implements
 * this interface with sensible, reusable behaviour.
 */
interface Test_Interface {

	/**
	 * Unique, stable identifier of this test (e.g. "external_ip").
	 *
	 * Used as array key for configuration and results, so it must never
	 * change once published, or consuming projects will break.
	 *
	 * @return string
	 */
	public function get_slug(): string;

	/**
	 * Set the configuration for this test run.
	 *
	 * Implementations should merge this with their own defaults.
	 *
	 * @param array<string,mixed> $config Configuration for this test.
	 * @return void
	 */
	public function set_config( array $config ): void;

	/**
	 * Run the test with the given configuration.
	 *
	 * @return void
	 */
	public function run(): void;

	/**
	 * Return the result of the last run() call.
	 *
	 * @return Result
	 */
	public function get_result(): Result;
}
