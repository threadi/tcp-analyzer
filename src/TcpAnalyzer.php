<?php
/**
 * File to handle the main TCP Analyzer tasks.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer;

use InvalidArgumentException;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests\Dns;
use TcpAnalyzer\Tests\ExternalIp;
use TcpAnalyzer\Tests\Http;
use TcpAnalyzer\Tests\TcpConnect;
use TcpAnalyzer\Tests\Traceroute;
use Throwable;

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
	 * Target filter handed to every test that has none in its own config.
	 *
	 * @var callable|null
	 */
	private $target_filter = null;

	/**
	 * Constructor for this object.
	 */
	public function __construct() {}

	/**
	 * Restrict the targets all tests may talk to.
	 *
	 * The filter is passed on as "target_filter" config to every test that
	 * does not bring its own, see Tests_Base::get_target_filter() for its
	 * signature. Target_Filter::public_only() is a ready-made filter that
	 * rejects loopback, private and other non-public addresses.
	 *
	 * Set this whenever a host or URL originates from user input.
	 *
	 * @param callable|null $filter The filter, or null to remove it.
	 * @return void
	 * @noinspection PhpUnused
	 */
	public function set_target_filter( ?callable $filter ): void {
		$this->target_filter = $filter;
	}

	/**
	 * Register a custom test class, or override a built-in one.
	 *
	 * @param string $slug  Unique slug for this test.
	 * @param string $test_class Fully qualified class name, must implement Test_Interface.
	 * @return void
	 *
	 * @throws InvalidArgumentException On any error.
	 */
	public function register_test( string $slug, string $test_class ): void {
		if ( ! is_a( $test_class, Test_Interface::class, true ) ) {
			throw new InvalidArgumentException( sprintf( 'Class "%s" must implement %s.', $test_class, Test_Interface::class ) );
		}

		$this->available_tests[ $slug ] = $test_class;
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
	 *
	 * @throws InvalidArgumentException On any error.
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

			if ( null !== $this->target_filter && ! array_key_exists( 'target_filter', $config ) ) {
				$config['target_filter'] = $this->target_filter;
			}

			/*
			 * A test that throws - a custom test, a target filter, a test
			 * that forgot to set its result - must not take the others down
			 * with it. It is reported as failed, with the class of what has
			 * been thrown: the message is free text and stays out.
			 */
			try {
				/**
				 * The test instance.
				 *
				 * @var Test_Interface $test
				 */
				$test = new $class();
				$test->set_config( $config );
				$test->run();

				$this->results[ $slug ] = $test->get_result();
			} catch ( Throwable $throwable ) {
				$this->results[ $slug ] = new Result( $slug, Status::ERROR, null, array( 'exception' => $throwable::class ), 'test_exception' );
			}
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
