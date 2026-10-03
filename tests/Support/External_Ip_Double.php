<?php
/**
 * File to hold a test double for the ExternalIp test class.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Tests\ExternalIp;

/**
 * ExternalIp with the HTTP layer replaced by a queue of canned responses.
 *
 * Each call to http_request() consumes the next queued response, which makes
 * the provider fallback chain observable without any network access.
 */
final class External_Ip_Double extends ExternalIp {

	/**
	 * Arguments of every http_request() call, in order.
	 *
	 * @var array<int,array{url:string,timeout:int,head_only:bool}>
	 */
	public array $calls = array();

	/**
	 * Queued responses, consumed front to back.
	 *
	 * @var array<int,array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}>
	 */
	public array $responses = array();

	/**
	 * Queue a successful response with the given body.
	 *
	 * @param string $body Response body.
	 * @return void
	 */
	public function queue_body( string $body ): void {
		$this->responses[] = array(
			'success'    => true,
			'body'       => $body,
			'http_code'  => 200,
			'timing'     => array( 'total_ms' => 10.0 ),
			'error_code' => null,
		);
	}

	/**
	 * Queue a failed response.
	 *
	 * @param string $error_code Machine-readable error identifier.
	 * @return void
	 */
	public function queue_failure( string $error_code = 'request_failed' ): void {
		$this->responses[] = array(
			'success'    => false,
			'body'       => null,
			'http_code'  => null,
			'timing'     => array(),
			'error_code' => $error_code,
		);
	}

	/**
	 * Queue a response that is flagged successful but carries no body.
	 *
	 * @return void
	 */
	public function queue_empty_body(): void {
		$this->responses[] = array(
			'success'    => true,
			'body'       => null,
			'http_code'  => 204,
			'timing'     => array( 'total_ms' => 5.0 ),
			'error_code' => null,
		);
	}

	/**
	 * {@inheritDoc}
	 */
	protected function http_request( string $url, int $timeout = 10, bool $head_only = false ): array {
		$this->calls[] = array(
			'url'       => $url,
			'timeout'   => $timeout,
			'head_only' => $head_only,
		);

		$response = array_shift( $this->responses );

		if ( null === $response ) {
			return array(
				'success'    => false,
				'body'       => null,
				'http_code'  => null,
				'timing'     => array(),
				'error_code' => 'no_response_queued',
			);
		}

		return $response;
	}

	/**
	 * Expose the target filter handed to the HTTP client.
	 *
	 * @return callable|null
	 */
	public function read_http_target_filter(): ?callable {
		return $this->http_target_filter();
	}
}
