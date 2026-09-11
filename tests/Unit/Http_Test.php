<?php
/**
 * File to test the HTTP request test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\PHPUnitTests\Support\Http_Double;
use TcpAnalyzer\Tests\Http;

/**
 * Tests for TcpAnalyzer\Tests\Http.
 *
 * The HTTP layer is replaced by Http_Double, so only the mapping from a
 * response to a Result is under test here - no request leaves the machine.
 */
#[CoversClass( Http::class )]
final class Http_Test extends TestCase {

	/**
	 * The double under test.
	 *
	 * @var Http_Double
	 */
	private Http_Double $http;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->http = new Http_Double();
	}

	/**
	 * The slug is part of the public contract.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_published_slug(): void {
		$this->assertSame( 'http', ( new Http() )->get_slug() );
	}

	/**
	 * By default a HEAD-only request with a 10 second timeout is sent.
	 *
	 * @return void
	 */
	#[Test]
	public function sends_a_head_request_with_the_default_timeout(): void {
		$this->http->set_config( array( 'url' => 'https://example.com' ) );
		$this->http->run();

		$this->assertSame(
			array(
				array(
					'url'       => 'https://example.com',
					'timeout'   => 10,
					'head_only' => true,
				),
			),
			$this->http->calls
		);
	}

	/**
	 * Timeout and request method can be overridden.
	 *
	 * @return void
	 */
	#[Test]
	public function passes_the_configured_timeout_and_method_through(): void {
		$this->http->set_config(
			array(
				'url'       => 'https://example.com',
				'timeout'   => 3,
				'head_only' => false,
			)
		);
		$this->http->run();

		$this->assertSame(
			array(
				'url'       => 'https://example.com',
				'timeout'   => 3,
				'head_only' => false,
			),
			$this->http->calls[0]
		);
	}

	/**
	 * A 2xx/3xx response is a success, the status code is the result value
	 * and the timing is carried over unchanged.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_status_code_and_timing_on_success(): void {
		$timing = array(
			'dns_ms'     => 12.1,
			'connect_ms' => 30.4,
			'tls_ms'     => 60.2,
			'ttfb_ms'    => 91.7,
			'total_ms'   => 98.3,
		);

		$this->http->response = array(
			'success'    => true,
			'body'       => null,
			'http_code'  => 200,
			'timing'     => $timing,
			'error_code' => null,
		);

		$this->http->set_config( array( 'url' => 'https://example.com' ) );
		$this->http->run();

		$result = $this->http->get_result();

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( 200, $result->get_value() );
		$this->assertNull( $result->get_error_code() );
		$this->assertSame( 98.3, $result->get_duration_ms() );
		$this->assertSame(
			array(
				'url'    => 'https://example.com',
				'timing' => $timing,
			),
			$result->get_data()
		);
	}

	/**
	 * Status codes outside the 200-399 range are a warning, not an error:
	 * the connection itself worked.
	 *
	 * @param int|null $http_code   The status code returned by the transport.
	 * @param Status   $expected    Expected result status.
	 * @param string|null $expected_error_code Expected error code.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_status_codes' )]
	public function maps_status_codes_to_a_result_status( ?int $http_code, Status $expected, ?string $expected_error_code ): void {
		$this->http->response = array(
			'success'    => true,
			'body'       => null,
			'http_code'  => $http_code,
			'timing'     => array( 'total_ms' => 12.0 ),
			'error_code' => null,
		);

		$this->http->set_config( array( 'url' => 'https://example.com' ) );
		$this->http->run();

		$result = $this->http->get_result();

		$this->assertSame( $expected, $result->get_status() );
		$this->assertSame( $expected_error_code, $result->get_error_code() );
		$this->assertSame( $http_code, $result->get_value() );
	}

	/**
	 * Data provider for maps_status_codes_to_a_result_status().
	 *
	 * @return array<string,array{0:int|null,1:Status,2:string|null}>
	 */
	public static function provide_status_codes(): array {
		return array(
			'ok'                 => array( 200, Status::SUCCESS, null ),
			'no content'         => array( 204, Status::SUCCESS, null ),
			'moved permanently'  => array( 301, Status::SUCCESS, null ),
			'upper bound'        => array( 399, Status::SUCCESS, null ),
			'lower bound'        => array( 200, Status::SUCCESS, null ),
			'informational'      => array( 199, Status::WARNING, 'http_status_not_ok' ),
			'bad request'        => array( 400, Status::WARNING, 'http_status_not_ok' ),
			'not found'          => array( 404, Status::WARNING, 'http_status_not_ok' ),
			'server error'       => array( 503, Status::WARNING, 'http_status_not_ok' ),
			'unknown status'     => array( null, Status::WARNING, 'http_status_not_ok' ),
		);
	}

	/**
	 * A transport failure keeps the reported error code.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_the_transport_error_code(): void {
		$this->http->response = array(
			'success'    => false,
			'body'       => null,
			'http_code'  => null,
			'timing'     => array( 'total_ms' => 10000.0 ),
			'error_code' => 'curl_errno_28',
		);

		$this->http->set_config( array( 'url' => 'https://example.com' ) );
		$this->http->run();

		$result = $this->http->get_result();

		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertNull( $result->get_value() );
		$this->assertSame( 'curl_errno_28', $result->get_error_code() );
		$this->assertSame( 10000.0, $result->get_duration_ms() );
		$this->assertSame(
			array(
				'url'    => 'https://example.com',
				'timing' => array( 'total_ms' => 10000.0 ),
			),
			$result->get_data()
		);
	}

	/**
	 * A failure without an error code falls back to a generic one, so the
	 * consuming project always has something to translate.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_back_to_a_generic_error_code(): void {
		$this->http->response = array(
			'success'    => false,
			'body'       => null,
			'http_code'  => null,
			'timing'     => array(),
			'error_code' => null,
		);

		$this->http->set_config( array( 'url' => 'https://example.com' ) );
		$this->http->run();

		$result = $this->http->get_result();

		$this->assertSame( 'http_request_failed', $result->get_error_code() );
		$this->assertNull( $result->get_duration_ms() );
		$this->assertSame( array(), $result->get_data()['timing'] );
	}

	/**
	 * Without a url nothing is requested.
	 *
	 * @return void
	 */
	#[Test]
	public function requires_a_url(): void {
		$this->http->set_config( array() );
		$this->http->run();

		$result = $this->http->get_result();

		$this->assertSame( array(), $this->http->calls );
		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertSame( 'invalid_config', $result->get_error_code() );
		$this->assertSame( array( 'missing_config' => array( 'url' ) ), $result->get_data() );
	}
}
