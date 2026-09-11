<?php
/**
 * File to provide a reusable, dependency-free HTTP client for tests.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Traits;

/**
 * Minimal HTTP client used by tests that need to send a request.
 *
 * Uses curl if available (for detailed connect/TLS/TTFB timing), falls
 * back to a stream context otherwise. Never throws - always returns a
 * structured array.
 */
trait Http_Client {

	/**
	 * Perform an HTTP request and return normalized, structured data.
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request (no body needed).
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	protected function http_request( string $url, int $timeout = 10, bool $head_only = false ): array {
		if ( function_exists( 'curl_init' ) ) {
			return $this->http_request_curl( $url, $timeout, $head_only );
		}

		return $this->http_request_stream( $url, $timeout, $head_only );
	}

	/**
	 * Request via curl. Provides detailed timing (DNS/connect/TLS/TTFB/total).
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	private function http_request_curl( string $url, int $timeout, bool $head_only ): array {
		$curl_handle = curl_init( $url );

		curl_setopt_array(
			$curl_handle,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => $timeout,
				CURLOPT_CONNECTTIMEOUT => min( $timeout, 8 ),
				CURLOPT_NOBODY         => $head_only,
				CURLOPT_FOLLOWLOCATION => true,
			)
		);

		$body  = curl_exec( $curl_handle );
		$errno = curl_errno( $curl_handle );

		if ( false === $body || 0 !== $errno ) {
			curl_close( $curl_handle );

			return array(
				'success'    => false,
				'body'       => null,
				'http_code'  => null,
				'timing'     => array(),
				'error_code' => 'curl_errno_' . $errno,
			);
		}

		$info = curl_getinfo( $curl_handle );

		/*
		 * The TLS handshake time is not part of the curl_getinfo() array, it
		 * has to be requested explicitly. It is 0.0 for an unencrypted
		 * connection, and false if libcurl cannot report it at all.
		 */
		$appconnect_time = curl_getinfo( $curl_handle, CURLINFO_APPCONNECT_TIME );

		curl_close( $curl_handle );

		return array(
			'success'    => true,
			'body'       => is_string( $body ) ? $body : null,
			'http_code'  => (int) $info['http_code'],
			'timing'     => array(
				'dns_ms'     => round( $info['namelookup_time'] * 1000, 2 ),
				'connect_ms' => round( $info['connect_time'] * 1000, 2 ),
				'tls_ms'     => round( (float) $appconnect_time * 1000, 2 ),
				'ttfb_ms'    => round( $info['starttransfer_time'] * 1000, 2 ),
				'total_ms'   => round( $info['total_time'] * 1000, 2 ),
			),
			'error_code' => null,
		);
	}

	/**
	 * Request via a stream context. Fallback if curl is unavailable, only total timing.
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	private function http_request_stream( string $url, int $timeout, bool $head_only ): array {
		$start   = microtime( true );
		$context = stream_context_create(
			array(
				'http' => array(
					'method'  => $head_only ? 'HEAD' : 'GET',
					'timeout' => $timeout,
				),
			)
		);

		$body     = @file_get_contents( $url, false, $context );
		$total_ms = round( ( microtime( true ) - $start ) * 1000, 2 );

		if ( false === $body ) {
			return array(
				'success'    => false,
				'body'       => null,
				'http_code'  => null,
				'timing'     => array( 'total_ms' => $total_ms ),
				'error_code' => 'request_failed',
			);
		}

		$status_code = null;

		/*
		 * $http_response_header is created in the local scope by the HTTP
		 * wrapper - but only by that one. A request through any other
		 * wrapper (file://, ftp://, ...) leaves the variable undefined, so
		 * it must never be read without a null coalescing guard.
		 */
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- $http_response_header is a PHP-native superglobal-like variable set by file_get_contents().
		// @phpstan-ignore nullCoalesce.variable (only the HTTP wrapper creates this variable, PHPStan assumes it always exists)
		$response_headers = $http_response_header ?? array();

		if ( isset( $response_headers[0] ) && preg_match( '/\s(\d{3})\s/', (string) $response_headers[0], $status_matches ) ) {
			$status_code = (int) $status_matches[1];
		}

		return array(
			'success'    => true,
			'body'       => $body,
			'http_code'  => $status_code,
			'timing'     => array( 'total_ms' => $total_ms ),
			'error_code' => null,
		);
	}
}