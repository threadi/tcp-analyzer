<?php
/**
 * File to test the reusable HTTP client trait.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;
use TcpAnalyzer\PHPUnitTests\Support\Http_Client_Double;
use TcpAnalyzer\Traits\Http_Client;

/**
 * Tests for TcpAnalyzer\Traits\Http_Client.
 *
 * Only the stream implementation is exercised, against local file:// URLs -
 * the curl implementation needs a real network peer and is therefore not
 * unit-testable. function_exists() is stubbed in the TcpAnalyzer\Traits
 * namespace to force the stream path regardless of the machine the suite
 * runs on.
 */
#[CoversTrait( Http_Client::class )]
final class Http_Client_Test extends TestCase {

	/**
	 * The double under test.
	 *
	 * @var Http_Client_Double
	 */
	private Http_Client_Double $client;

	/**
	 * Temporary files created during a test.
	 *
	 * @var string[]
	 */
	private array $temp_files = array();

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->client = new Http_Client_Double();
	}

	/**
	 * {@inheritDoc}
	 */
	protected function tearDown(): void {
		FunctionMocks::reset();

		foreach ( $this->temp_files as $temp_file ) {
			if ( is_file( $temp_file ) ) {
				unlink( $temp_file );
			}
		}

		$this->temp_files = array();

		parent::tearDown();
	}

	/**
	 * The implementation is chosen by the availability of curl.
	 *
	 * @return void
	 */
	#[Test]
	public function decides_by_the_availability_of_curl(): void {
		$checked = array();

		FunctionMocks::set_for_traits(
			'function_exists',
			static function ( string $function ) use ( &$checked ): bool {
				$checked[] = $function;

				return false;
			}
		);

		$this->client->request( $this->temp_url( 'irrelevant' ) );

		$this->assertSame( array( 'curl_init' ), $checked );
	}

	/**
	 * The stream implementation returns the body, and a total runtime.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_the_body_via_the_stream_implementation(): void {
		$this->force_stream_implementation();

		$response = $this->client->request( $this->temp_url( '203.0.113.42' ) );

		$this->assertTrue( $response['success'] );
		$this->assertSame( '203.0.113.42', $response['body'] );
		$this->assertNull( $response['error_code'] );
		$this->assertArrayHasKey( 'total_ms', $response['timing'] );
		$this->assertIsFloat( $response['timing']['total_ms'] );
		$this->assertGreaterThanOrEqual( 0.0, $response['timing']['total_ms'] );
	}

	/**
	 * Without HTTP response headers there is no status code - the consuming
	 * test has to cope with null.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_no_status_code_without_http_headers(): void {
		$this->force_stream_implementation();

		$response = $this->client->request( $this->temp_url( 'body' ) );

		$this->assertNull( $response['http_code'] );
	}

	/**
	 * A failing request never throws, it returns a structured failure.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_a_structured_failure_instead_of_throwing(): void {
		$this->force_stream_implementation();

		$response = $this->client->request( 'file:///does/not/exist/' . uniqid() );

		$this->assertFalse( $response['success'] );
		$this->assertNull( $response['body'] );
		$this->assertNull( $response['http_code'] );
		$this->assertSame( 'request_failed', $response['error_code'] );
		$this->assertArrayHasKey( 'total_ms', $response['timing'] );
	}

	/**
	 * The returned array always has the documented shape, in both outcomes.
	 *
	 * @return void
	 */
	#[Test]
	public function always_returns_the_documented_response_shape(): void {
		$this->force_stream_implementation();

		$expected_keys = array( 'success', 'body', 'http_code', 'timing', 'error_code' );

		$this->assertSame( $expected_keys, array_keys( $this->client->request( $this->temp_url( 'body' ) ) ) );
		$this->assertSame( $expected_keys, array_keys( $this->client->request( 'file:///nope/' . uniqid() ) ) );
	}

	/**
	 * Force the stream implementation by reporting curl as unavailable.
	 *
	 * @return void
	 */
	private function force_stream_implementation(): void {
		FunctionMocks::set_for_traits( 'function_exists', static fn( string $function ): bool => false );
	}

	/**
	 * Create a temporary file with the given content and return its URL.
	 *
	 * @param string $content Content of the file.
	 * @return string
	 */
	private function temp_url( string $content ): string {
		$path = (string) tempnam( sys_get_temp_dir(), 'tcp-analyzer-' );
		file_put_contents( $path, $content );

		$this->temp_files[] = $path;

		return 'file://' . $path;
	}
}
