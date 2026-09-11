<?php
/**
 * File to hold a thin wrapper exposing the Http_Client trait.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Traits\Http_Client;

/**
 * Exposes the protected http_request() of the Http_Client trait so the trait
 * can be tested on its own, independent of any concrete test class.
 */
final class Http_Client_Double {

	use Http_Client;

	/**
	 * Public wrapper around the trait's http_request().
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	public function request( string $url, int $timeout = 10, bool $head_only = false ): array {
		return $this->http_request( $url, $timeout, $head_only );
	}
}
