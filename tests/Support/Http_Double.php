<?php
/**
 * File to hold a test double for the Http test class.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Tests\Http;

/**
 * Http with the HTTP layer replaced.
 *
 * http_request() comes from the Http_Client trait and is protected, so a
 * subclass can override it - that is the seam used here to test the result
 * mapping of Http without any network access.
 */
final class Http_Double extends Http {

	/**
	 * Arguments of every http_request() call, in order.
	 *
	 * @var array<int,array{url:string,timeout:int,head_only:bool}>
	 */
	public array $calls = array();

	/**
	 * The canned response http_request() returns.
	 *
	 * @var array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	public array $response = array(
		'success'    => true,
		'body'       => null,
		'http_code'  => 200,
		'timing'     => array( 'total_ms' => 123.45 ),
		'error_code' => null,
	);

	/**
	 * {@inheritDoc}
	 */
	protected function http_request( string $url, int $timeout = 10, bool $head_only = false ): array {
		$this->calls[] = array(
			'url'       => $url,
			'timeout'   => $timeout,
			'head_only' => $head_only,
		);

		return $this->response;
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
