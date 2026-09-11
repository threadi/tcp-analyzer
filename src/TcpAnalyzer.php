<?php
/**
 * File to handle the main TCP Analyzer tasks.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer;

use InvalidArgumentException;
use TcpAnalyzer\Tests\Dns;
use TcpAnalyzer\Tests\ExternalIp;
use TcpAnalyzer\Tests\Http;
use TcpAnalyzer\Tests\TcpConnect;
use TcpAnalyzer\Tests\Traceroute;

/**
 * Main object to handle the TCP Analyzer tasks.
 *
 * Usage:
 *
 *   $analyzer = new TcpAnalyzer();
 *   $analyzer->set_tests( array(
 *       'external_ip' => array(),
 *       'dns'         => array( 'host' => 'example.com' ),
 *       'tcp_connect' => array( 'host' => 'example.com', 'port' => 443 ),
 *       'http'        => array( 'url' => 'https://example.com' ),
 *   ) );
 *   $analyzer->run();
 *   $results = $analyzer->get_results_as_array(); // slug => array, no free text.
 */
class TcpAnalyzer {

	/**
	 * Registered tests assigning of slug => fully qualified class name.
	 *
	 * @var array<string,class-string<Test_Interface>>
	 */
	private array $available_tests = array(
		'external_ip' => ExternalIp::class,
		'dns'         => Dns::class,
		'tcp_connect' => TcpConnect::class,
		'http'        => Http::class,
		'traceroute'  => Traceroute::class,
	);

	/**
	 * Tests configured to run for the next run() call, slug => config.
	 *
	 * @var array<string,array<string,mixed>>
	 */
	private array $tests_to_run = array();

	/**
	 * Results of the last run() call, slug => Result.
	 *
	 * @var array<string,Result>
	 */
	private array $results = array();

	/**
	 * Constructor for this object.
	 */
	public function __construct() {}

	/**
	 * Register a custom test class, or override a built-in one.
	 *
	 * @param string $slug  Unique slug for this test.
	 * @param string $class Fully qualified class name, must implement Test_Interface.
	 * @return void
	 */
	public function register_test( string $slug, string $class ): void {
		if ( ! is_a( $class, Test_Interface::class, true ) ) {
			throw new InvalidArgumentException( sprintf( 'Class "%s" must implement %s.', $class, Test_Interface::class ) );
		}

		$this->available_tests[ $slug ] = $class;
	}

	/**
	 * Return all available (built-in + registered) tests.
	 *
	 * @return array<string,class-string<Test_Interface>>
	 */
	public function get_available_tests(): array {
		return $this->available_tests;
	}

	/**
	 * Configure which tests to run, with which configuration.
	 *
	 * @param array<string,array<string,mixed>> $tests Slug => config array. An empty
	 *                                                  config array is valid for tests
	 *                                                  without required options.
	 * @return void
	 */
	public function set_tests( array $tests ): void {
		foreach ( $tests as $slug => $config ) {
			if ( ! is_string( $slug ) || ! isset( $this->available_tests[ $slug ] ) ) { // @phpstan-ignore function.alreadyNarrowedType
				throw new InvalidArgumentException( sprintf( 'Unknown test slug "%s".', $slug ) );
			}

			$this->tests_to_run[ $slug ] = is_array( $config ) ? $config : array(); // @phpstan-ignore function.alreadyNarrowedType
		}
	}

	/**
	 * Run the configured tests.
	 *
	 * @return void
	 */
	public function run(): void {
		$this->results = array();

		foreach ( $this->tests_to_run as $slug => $config ) {
			$class = $this->available_tests[ $slug ];

			/**
			 * The test instance.
			 *
			 * @var Test_Interface $test
			 */
			$test = new $class();
			$test->set_config( $config );
			$test->run();

			$this->results[ $slug ] = $test->get_result();
		}
	}

	/**
	 * Return the results of the last run() call as Result objects.
	 *
	 * @return array<string,Result>
	 */
	public function get_results(): array {
		return $this->results;
	}

	/**
	 * Return the results of the last run() call as plain arrays (e.g. for json_encode()).
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public function get_results_as_array(): array {
		return array_map( static fn( Result $result ): array => $result->to_array(), $this->results );
	}
}
