<?php
/**
 * File to test the external IP test.
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
use TcpAnalyzer\PHPUnitTests\Support\External_Ip_Double;
use TcpAnalyzer\Tests\ExternalIp;

/**
 * Tests for TcpAnalyzer\Tests\ExternalIp.
 *
 * The HTTP layer is replaced by a queue of canned responses, which makes the
 * provider fallback chain observable without any network access.
 */
#[CoversClass( ExternalIp::class )]
final class ExternalIp_Test extends TestCase {

	/**
	 * The double under test.
	 *
	 * @var External_Ip_Double
	 */
	private External_Ip_Double $test;

	/**
	 * {@inheritDoc}
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->test = new External_Ip_Double();
	}

	/**
	 * The slug is part of the public contract.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_the_published_slug(): void {
		$this->assertSame( 'external_ip', ( new ExternalIp() )->get_slug() );
	}

	/**
	 * The first provider is asked first, with the default timeout, and a
	 * full-body (not HEAD) request.
	 *
	 * @return void
	 */
	#[Test]
	public function asks_the_first_provider_with_the_default_timeout(): void {
		$this->test->queue_body( '{"ip":"203.0.113.42"}' );

		$this->test->set_config( array() );
		$this->test->run();

		$this->assertSame(
			array(
				array(
					'url'       => 'https://api.ipify.org?format=json',
					'timeout'   => 5,
					'head_only' => false,
				),
			),
			$this->test->calls
		);
	}

	/**
	 * A JSON body with an "ip" key is unwrapped, and the provider that
	 * answered is reported in the result data.
	 *
	 * @return void
	 */
	#[Test]
	public function reads_the_ip_from_a_json_body(): void {
		$this->test->queue_body( '{"ip":"203.0.113.42"}' );

		$this->test->set_config( array() );
		$this->test->run();

		$result = $this->test->get_result();

		$this->assertSame( Status::SUCCESS, $result->get_status() );
		$this->assertSame( '203.0.113.42', $result->get_value() );
		$this->assertSame( array( 'provider' => 'https://api.ipify.org?format=json' ), $result->get_data() );
		$this->assertNull( $result->get_error_code() );
		$this->assertIsFloat( $result->get_duration_ms() );
	}

	/**
	 * A plain text body is accepted too, including trailing whitespace.
	 *
	 * @param string $body     The response body.
	 * @param string $expected The expected IP.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_valid_bodies' )]
	public function accepts_valid_ip_bodies( string $body, string $expected ): void {
		$this->test->queue_body( $body );

		$this->test->set_config( array() );
		$this->test->run();

		$this->assertSame( $expected, $this->test->get_result()->get_value() );
	}

	/**
	 * Data provider for accepts_valid_ip_bodies().
	 *
	 * @return array<string,array{0:string,1:string}>
	 */
	public static function provide_valid_bodies(): array {
		return array(
			'plain ipv4'          => array( '203.0.113.42', '203.0.113.42' ),
			'ipv4 with newline'   => array( "203.0.113.42\n", '203.0.113.42' ),
			'ipv4 with spaces'    => array( '  203.0.113.42  ', '203.0.113.42' ),
			'ipv6'                => array( '2001:db8::1', '2001:db8::1' ),
			'json with whitespace' => array( " {\"ip\":\"203.0.113.42\"}\n", '203.0.113.42' ),
			'json with padded ip' => array( '{"ip":" 203.0.113.42 "}', '203.0.113.42' ),
		);
	}

	/**
	 * A failing provider is skipped and the next one is tried.
	 *
	 * @return void
	 */
	#[Test]
	public function falls_back_to_the_next_provider(): void {
		$this->test->queue_failure();
		$this->test->queue_body( '203.0.113.9' );

		$this->test->set_config( array() );
		$this->test->run();

		$result = $this->test->get_result();

		$this->assertCount( 2, $this->test->calls );
		$this->assertSame( '203.0.113.9', $result->get_value() );
		$this->assertSame( array( 'provider' => 'https://ifconfig.me/ip' ), $result->get_data() );
	}

	/**
	 * A response that is technically successful but carries no usable IP is
	 * skipped as well.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_responses_without_a_usable_ip(): void {
		$this->test->queue_empty_body();
		$this->test->queue_body( 'not-an-ip' );
		$this->test->queue_body( '203.0.113.7' );

		$this->test->set_config( array() );
		$this->test->run();

		$this->assertCount( 3, $this->test->calls );
		$this->assertSame( '203.0.113.7', $this->test->get_result()->get_value() );
	}

	/**
	 * A JSON body without an "ip" key does not accidentally pass as an IP.
	 *
	 * @return void
	 */
	#[Test]
	public function rejects_a_json_body_without_an_ip_key(): void {
		$this->test->set_config( array( 'providers' => array( 'https://example.com/ip' ) ) );
		$this->test->queue_body( '{"address":"203.0.113.42"}' );
		$this->test->run();

		$this->assertSame( 'external_ip_unavailable', $this->test->get_result()->get_error_code() );
	}

	/**
	 * If every provider fails, the result is an error without any provider
	 * specific data.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_an_error_when_all_providers_fail(): void {
		$this->test->queue_failure();
		$this->test->queue_failure();
		$this->test->queue_failure();

		$this->test->set_config( array() );
		$this->test->run();

		$result = $this->test->get_result();

		$this->assertCount( 3, $this->test->calls );
		$this->assertSame( Status::ERROR, $result->get_status() );
		$this->assertNull( $result->get_value() );
		$this->assertSame( 'external_ip_unavailable', $result->get_error_code() );
		$this->assertSame( array(), $result->get_data() );
		$this->assertIsFloat( $result->get_duration_ms() );
	}

	/**
	 * Providers and timeout can be replaced, e.g. with an internal service.
	 *
	 * @return void
	 */
	#[Test]
	public function uses_custom_providers_and_timeout(): void {
		$this->test->queue_body( '198.51.100.5' );

		$this->test->set_config(
			array(
				'providers' => array( 'https://ip.example.internal' ),
				'timeout'   => 2,
			)
		);
		$this->test->run();

		$this->assertSame(
			array(
				array(
					'url'       => 'https://ip.example.internal',
					'timeout'   => 2,
					'head_only' => false,
				),
			),
			$this->test->calls
		);
		$this->assertSame( '198.51.100.5', $this->test->get_result()->get_value() );
	}

	/**
	 * An empty provider list is not an exception, just an error result.
	 *
	 * @return void
	 */
	#[Test]
	public function reports_an_error_without_any_provider(): void {
		$this->test->set_config( array( 'providers' => array() ) );
		$this->test->run();

		$this->assertSame( array(), $this->test->calls );
		$this->assertSame( 'external_ip_unavailable', $this->test->get_result()->get_error_code() );
	}

	/**
	 * The test needs no configuration at all, the defaults are enough.
	 *
	 * @return void
	 */
	#[Test]
	public function runs_with_the_default_config(): void {
		$this->test->queue_body( '203.0.113.42' );

		$this->test->set_config( array() );
		$this->test->run();

		$this->assertSame( Status::SUCCESS, $this->test->get_result()->get_status() );
	}

	/**
	 * The configured target filter is handed to the HTTP client.
	 *
	 * @return void
	 */
	#[Test]
	public function hands_the_target_filter_to_the_http_client(): void {
		$filter = static fn( string $host, string $ip, ?int $port ): bool => true;
		$double = new External_Ip_Double();

		$double->set_config( array() );

		$this->assertNull( $double->read_http_target_filter() );

		$double->set_config( array( 'target_filter' => $filter ) );

		$this->assertSame( $filter, $double->read_http_target_filter() );
	}

	/**
	 * The real test - no double - skips a provider the filter rejects,
	 * before anything is sent.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_a_provider_the_filter_rejects(): void {
		$asked = array();

		$test = new ExternalIp();
		$test->set_config(
			array(
				'providers'     => array( 'http://127.0.0.1:9/ip', 'http://10.0.0.1/ip' ),
				'target_filter' => static function ( string $host, string $ip, ?int $port ) use ( &$asked ): bool {
					$asked[] = array( $host, $ip, $port );

					return false;
				},
			)
		);
		$test->run();

		$this->assertSame(
			array(
				array( '127.0.0.1', '127.0.0.1', 9 ),
				array( '10.0.0.1', '10.0.0.1', 80 ),
			),
			$asked
		);
		$this->assertSame( Status::ERROR, $test->get_result()->get_status() );
		$this->assertSame( 'external_ip_unavailable', $test->get_result()->get_error_code() );
	}

	/**
	 * Anything but a URL in the provider list is skipped, without a PHP warning.
	 *
	 * @return void
	 */
	#[Test]
	public function skips_providers_that_are_not_strings(): void {
		$double = new External_Ip_Double();
		$double->queue_body( '203.0.113.42' );

		$double->set_config(
			array(
				'providers' => array( array( 'https://nested.example' ), null, 42, new \stdClass(), 'https://provider.example/ip' ),
				'timeout'   => array( 1 ),
			)
		);
		$double->run();

		$this->assertCount( 1, $double->calls );
		$this->assertSame( 'https://provider.example/ip', $double->calls[0]['url'] );
		$this->assertSame( 5, $double->calls[0]['timeout'] );
		$this->assertSame( '203.0.113.42', $double->get_result()->get_value() );
	}

	/**
	 * Credentials of a provider URL are not repeated in the result.
	 *
	 * @return void
	 */
	#[Test]
	public function keeps_credentials_out_of_the_result(): void {
		$double = new External_Ip_Double();
		$double->queue_body( '203.0.113.42' );

		$double->set_config( array( 'providers' => array( 'https://user:secret@provider.example/ip' ) ) );
		$double->run();

		$this->assertSame( 'https://user:secret@provider.example/ip', $double->calls[0]['url'] );
		$this->assertSame( array( 'provider' => 'https://provider.example/ip' ), $double->get_result()->get_data() );
	}
}
