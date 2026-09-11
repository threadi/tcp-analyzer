<?php
/**
 * File to test the Result object.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use JsonSerializable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Result;

/**
 * Tests for TcpAnalyzer\Result.
 */
#[CoversClass( Result::class )]
final class Result_Test extends TestCase {

	/**
	 * All constructor arguments are returned unchanged by the getters.
	 *
	 * @return void
	 */
	#[Test]
	public function exposes_all_constructor_arguments(): void {
		$result = new Result( 'dns', Status::SUCCESS, '93.184.216.34', array( 'host' => 'example.com' ), null, 12.1 );

		$this->assertSame( 'dns', $result->get_slug() );
		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( '93.184.216.34', $result->get_value() );
		$this->assertSame( array( 'host' => 'example.com' ), $result->get_data() );
		$this->assertNull( $result->get_error_code() );
		$this->assertSame( 12.1, $result->get_duration_ms() );
	}

	/**
	 * Everything except slug and status is optional.
	 *
	 * @return void
	 */
	#[Test]
	public function applies_defaults_for_optional_arguments(): void {
		$result = new Result( 'dns', Status::ERROR );

		$this->assertNull( $result->get_value() );
		$this->assertSame( array(), $result->get_data() );
		$this->assertNull( $result->get_error_code() );
		$this->assertNull( $result->get_duration_ms() );
	}

	/**
	 * The value is not restricted to scalars.
	 *
	 * @return void
	 */
	#[Test]
	public function accepts_structured_values(): void {
		$hops = array(
			array(
				'hop'      => 1,
				'ip'       => '192.168.178.1',
				'times_ms' => array( 0.512, 0.48 ),
			),
		);

		$result = new Result( 'traceroute', Status::SUCCESS, $hops );

		$this->assertSame( $hops, $result->get_value() );
	}

	/**
	 * Only SUCCESS counts as a successful run.
	 *
	 * @param Status $status   The status to check.
	 * @param bool   $expected Expected outcome of is_success().
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_statuses' )]
	public function reports_success_only_for_status_success( Status $status, bool $expected ): void {
		$result = new Result( 'dns', $status );

		$this->assertSame( $expected, $result->is_success() );
	}

	/**
	 * Data provider for reports_success_only_for_status_success().
	 *
	 * @return array<string,array{0:Status,1:bool}>
	 */
	public static function provide_statuses(): array {
		return array(
			'success' => array( Status::SUCCESS, true ),
			'warning' => array( Status::WARNING, false ),
			'error'   => array( Status::ERROR, false ),
			'skipped' => array( Status::SKIPPED, false ),
		);
	}

	/**
	 * to_array() returns the documented, stable key set, with the status as
	 * its string value rather than as an enum instance.
	 *
	 * @return void
	 */
	#[Test]
	public function converts_to_a_plain_array(): void {
		$result = new Result( 'tcp_connect', Status::ERROR, null, array( 'port' => 443 ), 'tcp_connect_timeout', 8000.0 );

		$this->assertSame(
			array(
				'slug'        => 'tcp_connect',
				'status'      => 'error',
				'value'       => null,
				'data'        => array( 'port' => 443 ),
				'error_code'  => 'tcp_connect_timeout',
				'duration_ms' => 8000.0,
			),
			$result->to_array()
		);
	}

	/**
	 * jsonSerialize() must not diverge from to_array().
	 *
	 * @return void
	 */
	#[Test]
	public function serializes_to_json_like_the_array_representation(): void {
		$result = new Result( 'http', Status::WARNING, 503, array( 'url' => 'https://example.com' ), 'http_status_not_ok', 42.0 );

		$this->assertInstanceOf( JsonSerializable::class, $result );
		$this->assertSame( $result->to_array(), $result->jsonSerialize() );
		$this->assertJsonStringEqualsJsonString(
			(string) json_encode( $result->to_array() ),
			(string) json_encode( $result )
		);
	}

	/**
	 * The result carries no human readable text, only machine readable codes.
	 *
	 * @return void
	 */
	#[Test]
	public function carries_no_free_text_keys(): void {
		$result = new Result( 'dns', Status::ERROR, null, array( 'host' => 'example.com' ), 'dns_resolution_failed' );

		$this->assertArrayNotHasKey( 'message', $result->to_array() );
		$this->assertArrayNotHasKey( 'error_message', $result->to_array() );
		$this->assertSame( 'dns_resolution_failed', $result->get_error_code() );
	}
}
