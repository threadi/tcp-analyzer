<?php
/**
 * File to test the main TcpAnalyzer object.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use InvalidArgumentException;
use Error;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;
use TcpAnalyzer\PHPUnitTests\Support\Other_Spy_Check;
use TcpAnalyzer\PHPUnitTests\Support\Spy_Check;
use TcpAnalyzer\PHPUnitTests\Support\Throwing_Check;
use TcpAnalyzer\Result;
use TcpAnalyzer\TcpAnalyzer;
use TcpAnalyzer\Tests\Dns;
use TcpAnalyzer\Tests\ExternalIp;
use TcpAnalyzer\Tests\Http;
use TcpAnalyzer\Tests\TcpConnect;
use TcpAnalyzer\Tests\Traceroute;

/**
 * Tests for TcpAnalyzer\TcpAnalyzer.
 *
 * All runs use registered spy tests, so no built-in test - and therefore no
 * network access - is triggered here.
 */
#[CoversClass( TcpAnalyzer::class )]
final class TcpAnalyzer_Test extends TestCase {

	/**
	 * The object under test.
	 *
	 * @var TcpAnalyzer
	 */
	private TcpAnalyzer $analyzer;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		Spy_Check::reset();

		$this->analyzer = new TcpAnalyzer();
	}

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		Spy_Check::reset();

		parent::tearDown();
	}

	/**
	 * The built-in tests are available out of the box, under their published
	 * slugs. These slugs are part of the public contract.
	 *
	 * @return void
	 */
	#[Test]
	public function ships_the_built_in_tests(): void {
		$this->assertSame(
			array(
				'external_ip' => ExternalIp::class,
				'dns'         => Dns::class,
				'tcp_connect' => TcpConnect::class,
				'http'        => Http::class,
				'traceroute'  => Traceroute::class,
			),
			$this->analyzer->get_available_tests()
		);
	}

	/**
	 * Custom tests can be added under a new slug.
	 *
	 * @return void
	 */
	#[Test]
	public function registers_a_custom_test(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );

		$available = $this->analyzer->get_available_tests();

		$this->assertArrayHasKey( 'spy', $available );
		$this->assertSame( Spy_Check::class, $available['spy'] );
		$this->assertCount( 6, $available );
	}

	/**
	 * An existing slug can be overridden, e.g. to replace a built-in test.
	 *
	 * @return void
	 */
	#[Test]
	public function overrides_a_built_in_test(): void {
		$this->analyzer->register_test( 'dns', Spy_Check::class );

		$available = $this->analyzer->get_available_tests();

		$this->assertSame( Spy_Check::class, $available['dns'] );
		$this->assertCount( 5, $available );
	}

	/**
	 * Classes that do not implement the interface are rejected.
	 *
	 * @return void
	 */
	#[Test]
	public function rejects_a_class_not_implementing_the_interface(): void {
		$this->expectException( InvalidArgumentException::class );
		$this->expectExceptionMessage( 'must implement TcpAnalyzer\Test_Interface' );

		$this->analyzer->register_test( 'invalid', stdClass::class );
	}

	/**
	 * A class name that does not exist at all is rejected as well, rather
	 * than failing later with a fatal error inside run().
	 *
	 * @return void
	 */
	#[Test]
	public function rejects_an_unknown_class_name(): void {
		$this->expectException( InvalidArgumentException::class );

		$this->analyzer->register_test( 'invalid', 'TcpAnalyzer\\Does\\Not\\Exist' );
	}

	/**
	 * Configuring an unregistered slug fails fast.
	 *
	 * @return void
	 */
	#[Test]
	public function rejects_an_unknown_test_slug(): void {
		$this->expectException( InvalidArgumentException::class );
		$this->expectExceptionMessage( 'Unknown test slug "nope".' );

		$this->analyzer->set_tests( array( 'nope' => array() ) );
	}

	/**
	 * set_tests() is not atomic: slugs processed before the invalid one stay
	 * configured and will run. Pinned here so a future change to that
	 * behaviour is a conscious decision.
	 *
	 * @return void
	 */
	#[Test]
	public function keeps_tests_configured_before_a_rejected_slug(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );

		try {
			$this->analyzer->set_tests(
				array(
					'spy'  => array(),
					'nope' => array(),
				)
			);
		} catch ( InvalidArgumentException ) {
			$this->addToAssertionCount( 1 );
		}

		$this->analyzer->run();

		$this->assertArrayHasKey( 'spy', $this->analyzer->get_results() );
	}

	/**
	 * Without a run there are no results.
	 *
	 * @return void
	 */
	#[Test]
	public function has_no_results_before_the_first_run(): void {
		$this->assertSame( array(), $this->analyzer->get_results() );
		$this->assertSame( array(), $this->analyzer->get_results_as_array() );
	}

	/**
	 * Running without configured tests is a no-op, not an error.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_without_configured_tests(): void {
		$this->analyzer->run();

		$this->assertSame( array(), $this->analyzer->get_results() );
		$this->assertSame( 0, Spy_Check::$instances );
	}

	/**
	 * run() instantiates the test, hands over its config and collects the
	 * result under the configured slug.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_a_configured_test_and_collects_its_result(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->set_tests( array( 'spy' => array( 'host' => 'example.com' ) ) );
		$this->analyzer->run();

		$results = $this->analyzer->get_results();

		$this->assertSame( 1, Spy_Check::$instances );
		$this->assertSame( array( 'host' => 'example.com' ), Spy_Check::$configs['spy'] );
		$this->assertArrayHasKey( 'spy', $results );
		$this->assertInstanceOf( Result::class, $results['spy'] );
		$this->assertSame( 'spy-value', $results['spy']->get_value() );
	}

	/**
	 * Several tests run in the order they were configured.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_several_tests_in_configuration_order(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->register_test( 'other_spy', Other_Spy_Check::class );
		$this->analyzer->set_tests(
			array(
				'other_spy' => array( 'first' => true ),
				'spy'       => array( 'second' => true ),
			)
		);
		$this->analyzer->run();

		$this->assertSame( array( 'other_spy', 'spy' ), array_keys( $this->analyzer->get_results() ) );
		$this->assertSame( 2, Spy_Check::$instances );
	}

	/**
	 * Repeated set_tests() calls add to the configuration instead of
	 * replacing it, and the last config for a slug wins.
	 *
	 * @return void
	 */
	#[Test]
	public function adds_up_repeated_set_tests_calls(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->register_test( 'other_spy', Other_Spy_Check::class );

		$this->analyzer->set_tests( array( 'spy' => array( 'round' => 1 ) ) );
		$this->analyzer->set_tests( array( 'other_spy' => array() ) );
		$this->analyzer->set_tests( array( 'spy' => array( 'round' => 2 ) ) );

		$this->analyzer->run();

		$this->assertSame( array( 'spy', 'other_spy' ), array_keys( $this->analyzer->get_results() ) );
		$this->assertSame( array( 'round' => 2 ), Spy_Check::$configs['spy'] );
	}

	/**
	 * A fresh run starts from an empty result set.
	 *
	 * @return void
	 */
	#[Test]
	public function resets_the_results_on_every_run(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->set_tests( array( 'spy' => array() ) );

		$this->analyzer->run();
		$first = $this->analyzer->get_results();

		$this->analyzer->run();
		$second = $this->analyzer->get_results();

		$this->assertCount( 1, $second );
		$this->assertNotSame( $first['spy'], $second['spy'] );
		$this->assertSame( 2, Spy_Check::$instances );
	}

	/**
	 * get_results_as_array() returns the same data, but as plain arrays that
	 * can be handed to json_encode() directly.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_the_results_as_plain_arrays(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->set_tests( array( 'spy' => array() ) );
		$this->analyzer->run();

		$this->assertSame(
			array(
				'spy' => array(
					'slug'        => 'spy',
					'status'      => 'success',
					'value'       => 'spy-value',
					'data'        => array( 'slug' => 'spy' ),
					'error_code'  => null,
					'duration_ms' => 1.23,
				),
			),
			$this->analyzer->get_results_as_array()
		);
	}

	/**
	 * A target filter set on the analyzer reaches every test.
	 *
	 * @return void
	 */
	#[Test]
	public function hands_its_target_filter_to_every_test(): void {
		$filter = static fn( string $host, string $ip, ?int $port ): bool => true;

		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->register_test( 'other_spy', Other_Spy_Check::class );
		$this->analyzer->set_target_filter( $filter );
		$this->analyzer->set_tests(
			array(
				'spy'       => array( 'host' => 'example.com' ),
				'other_spy' => array(),
			)
		);
		$this->analyzer->run();

		$this->assertSame(
			array(
				'host'          => 'example.com',
				'target_filter' => $filter,
			),
			Spy_Check::$configs['spy']
		);
		$this->assertSame( array( 'target_filter' => $filter ), Spy_Check::$configs['other_spy'] );
	}

	/**
	 * A target filter in the config of a test wins over the one of the
	 * analyzer - including an explicit null, which opts that test out.
	 *
	 * @return void
	 */
	#[Test]
	public function keeps_the_target_filter_a_test_brings_along(): void {
		$global = static fn( string $host, string $ip, ?int $port ): bool => true;
		$own    = static fn( string $host, string $ip, ?int $port ): bool => false;

		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->register_test( 'other_spy', Other_Spy_Check::class );
		$this->analyzer->set_target_filter( $global );
		$this->analyzer->set_tests(
			array(
				'spy'       => array( 'target_filter' => $own ),
				'other_spy' => array( 'target_filter' => null ),
			)
		);
		$this->analyzer->run();

		$this->assertSame( $own, Spy_Check::$configs['spy']['target_filter'] );
		$this->assertNull( Spy_Check::$configs['other_spy']['target_filter'] );
	}

	/**
	 * Without a target filter the config of a test stays untouched, and
	 * the filter can be removed again.
	 *
	 * @return void
	 */
	#[Test]
	public function leaves_the_config_alone_without_a_target_filter(): void {
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->set_tests( array( 'spy' => array( 'host' => 'example.com' ) ) );

		$this->analyzer->run();

		$this->assertSame( array( 'host' => 'example.com' ), Spy_Check::$configs['spy'] );

		$this->analyzer->set_target_filter( static fn( string $host, string $ip, ?int $port ): bool => true );
		$this->analyzer->set_target_filter( null );
		$this->analyzer->run();

		$this->assertSame( array( 'host' => 'example.com' ), Spy_Check::$configs['spy'] );
	}

	/**
	 * A test that throws is reported as failed - with the class of what was
	 * thrown, but without its message - and the tests after it still run.
	 *
	 * @param string $mode             The way the test fails.
	 * @param string $expected_class   The class reported in the result.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_failing_tests' )]
	public function reports_a_test_that_throws_and_runs_the_others( string $mode, string $expected_class ): void {
		$this->analyzer->register_test( 'throwing', Throwing_Check::class );
		$this->analyzer->register_test( 'spy', Spy_Check::class );
		$this->analyzer->set_tests(
			array(
				'throwing' => array( 'mode' => $mode ),
				'spy'      => array(),
			)
		);

		$this->analyzer->run();

		$results = $this->analyzer->get_results();

		$this->assertSame( array( 'throwing', 'spy' ), array_keys( $results ) );
		$this->assertSame( 'error', $results['throwing']->get_status()->value );
		$this->assertSame( 'test_exception', $results['throwing']->get_error_code() );
		$this->assertSame( array( 'exception' => $expected_class ), $results['throwing']->get_data() );
		$this->assertNull( $results['throwing']->get_value() );
		$this->assertStringNotContainsString( 'message', (string) json_encode( $this->analyzer->get_results_as_array() ) );
		$this->assertSame( 'spy-value', $results['spy']->get_value() );
	}

	/**
	 * Data provider: ways a test can fail, and the class reported for it.
	 *
	 * @return array<string,array{string,string}>
	 */
	public static function provide_failing_tests(): array {
		return array(
			'an exception'            => array( 'throw', LogicException::class ),
			'a PHP error'             => array( 'error', Error::class ),
			'no result has been set'  => array( 'silent', RuntimeException::class ),
		);
	}

	/**
	 * A target filter that throws is reported the same way.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_a_target_filter_that_throws(): void {
		$this->analyzer->set_target_filter(
			static function ( string $host, string $ip, ?int $port ): bool {
				throw new LogicException( 'A message that must not show up in any result.' );
			}
		);
		$this->analyzer->set_tests(
			array(
				'tcp_connect' => array(
					'host' => '192.0.2.1',
					'port' => 443,
				),
			)
		);

		$this->analyzer->run();

		$result = $this->analyzer->get_results()['tcp_connect'];

		$this->assertSame( 'test_exception', $result->get_error_code() );
		$this->assertSame( array( 'exception' => LogicException::class ), $result->get_data() );
	}
}
