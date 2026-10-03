<?php
/**
 * File to provide a reusable, dependency-free HTTP client for tests.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Traits;

/**
 * Minimal HTTP client used by tests that need to send a request.
 *
 * Uses curl if available (for detailed connect/TLS/TTFB timing), falls
 * back to a stream context otherwise. Never throws - always returns a
 * structured array.
 *
 * The client is deliberately narrow, as the URL may originate from user
 * input of the consuming project:
 * - Only http:// and https:// URLs are requested. Without this, the stream
 *   fallback would happily open file://, php:// or ftp:// URLs.
 * - Redirects are not followed. A 3xx response is returned as it is, so a
 *   harmless looking URL cannot send the request on to an internal address.
 * - If a target filter is set (see http_target_filter()), the host is
 *   resolved once, the filter decides about the resulting IP, and the
 *   connection is pinned to exactly that IP. Such a request never goes
 *   through a proxy.
 * - Not more than http_max_body_bytes() of the response body are read, and
 *   the body of a response to a HEAD request is not read at all. A server
 *   cannot exhaust the memory by sending an endless response.
 * - The timeout is the limit for the whole request. The stream
 *   implementation cannot enforce that while the response headers come in,
 *   there it only limits every single read.
 *
 * @phpstan-type Http_Target array{error_code:?string,url:string,stream_url:string,host:string,port:int,ip:?string,is_https:bool,resolve_ms:float}
 */
trait Http_Client {

	use Target_Guard;

	/**
	 * Return the filter deciding which targets may be requested, if any.
	 *
	 * Override this in the using class to restrict the targets. See
	 * Target_Guard::guard_target() for the signature of the filter.
	 *
	 * @return callable|null
	 */
	protected function http_target_filter(): ?callable {
		return null;
	}

	/**
	 * Return the maximum number of bytes read from a response body.
	 *
	 * A longer body is cut off, the request still counts as successful: the
	 * tests are interested in the status code and the timing, or in a body
	 * of a few bytes. Override this in the using class to change the limit.
	 *
	 * @return int
	 */
	protected function http_max_body_bytes(): int {
		return 1048576;
	}

	/**
	 * Return a URL without the credentials it may carry.
	 *
	 * For everything that ends up in a result: a result is meant to be
	 * shown, logged or sent to a browser, a password is not.
	 *
	 * @param string $url The URL.
	 * @return string
	 */
	protected function http_url_without_credentials( string $url ): string {
		return (string) preg_replace( '#\A([A-Za-z][A-Za-z0-9+.-]*://)[^/?\#]*@#', '$1', $url );
	}

	/**
	 * Perform an HTTP request and return normalized, structured data.
	 *
	 * Possible error codes: "invalid_url", "url_scheme_not_allowed",
	 * "curl_setup_failed", "curl_errno_<n>" resp. "request_failed", and -
	 * only with a target filter - "invalid_host", "dns_resolution_failed"
	 * and "target_rejected".
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request (no body needed).
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	protected function http_request( string $url, int $timeout = 10, bool $head_only = false ): array {
		$target = $this->prepare_http_target( $url );

		if ( null !== $target['error_code'] ) {
			return $this->http_failure( $target['error_code'] );
		}

		// Keep the timeout within what curl accepts: at least a second, at most its limit of 2147483 seconds.
		$timeout = max( 1, min( $timeout, 2147483 ) );

		/*
		 * Pinning the IP needs CURLOPT_CONNECT_TO, which a libcurl older
		 * than 7.49 does not have. The stream implementation can always pin,
		 * so it takes over in that case.
		 */
		$curl_can_pin = null === $target['ip'] || defined( 'CURLOPT_CONNECT_TO' );

		if ( function_exists( 'curl_init' ) && $curl_can_pin ) {
			return $this->http_request_curl( $target, $timeout, $head_only );
		}

		return $this->http_request_stream( $target, $timeout, $head_only );
	}

	/**
	 * Validate the URL and - if a target filter is set - resolve and check its host.
	 *
	 * With a target filter the URL is rebuilt from its parsed components
	 * instead of being passed on as given. That way curl cannot read a
	 * different host out of a creatively written URL than the one that has
	 * been checked here.
	 *
	 * @param string $url The URL to request.
	 * @return array<string,mixed> The prepared target, see the Http_Target type of this trait.
	 *
	 * @phpstan-return Http_Target
	 */
	private function prepare_http_target( string $url ): array {
		$target = array(
			'error_code' => null,
			'url'        => $url,
			'stream_url' => $url,
			'host'       => '',
			'port'       => 0,
			'ip'         => null,
			'is_https'   => false,
			'resolve_ms' => 0.0,
		);

		// Whitespace and control characters have no place in a URL, a line break could even smuggle in a header.
		$parts = 1 === preg_match( '/[\x00-\x20\x7f]/', $url ) ? false : parse_url( $url );

		if ( ! is_array( $parts ) || ! isset( $parts['scheme'] ) ) {
			$target['error_code'] = 'invalid_url';

			return $target;
		}

		$scheme = strtolower( $parts['scheme'] );

		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			$target['error_code'] = 'url_scheme_not_allowed';

			return $target;
		}

		if ( ! isset( $parts['host'] ) || '' === $parts['host'] ) {
			$target['error_code'] = 'invalid_url';

			return $target;
		}

		// Port 0 is no port: the stream wrapper would silently connect to the default port instead.
		if ( isset( $parts['port'] ) && $parts['port'] < 1 ) {
			$target['error_code'] = 'invalid_url';

			return $target;
		}

		$target['host']     = $parts['host'];
		$target['port']     = $parts['port'] ?? ( 'https' === $scheme ? 443 : 80 );
		$target['is_https'] = 'https' === $scheme;

		$filter = $this->http_target_filter();

		if ( null === $filter ) {
			return $target;
		}

		$guarded = $this->guard_target( $target['host'], $target['port'], $filter );

		$target['resolve_ms'] = $guarded['resolve_ms'];

		if ( null === $guarded['ip'] ) {
			$target['error_code'] = $guarded['error_code'] ?? 'target_rejected';

			return $target;
		}

		$userinfo = '';

		if ( isset( $parts['user'] ) ) {
			$userinfo = rawurlencode( rawurldecode( $parts['user'] ) );

			if ( isset( $parts['pass'] ) ) {
				$userinfo .= ':' . rawurlencode( rawurldecode( $parts['pass'] ) );
			}

			$userinfo .= '@';
		}

		$port_suffix = isset( $parts['port'] ) ? ':' . $parts['port'] : '';
		$path        = $parts['path'] ?? '/';
		$path        = str_starts_with( $path, '/' ) ? $path : '/' . $path;
		$remainder   = $port_suffix . $path . ( isset( $parts['query'] ) ? '?' . $parts['query'] : '' );

		$ip_as_host = str_contains( $guarded['ip'], ':' ) ? '[' . $guarded['ip'] . ']' : $guarded['ip'];

		$target['ip']         = $guarded['ip'];
		$target['url']        = $scheme . '://' . $userinfo . $target['host'] . $remainder;
		$target['stream_url'] = $scheme . '://' . $userinfo . $ip_as_host . $remainder;

		return $target;
	}

	/**
	 * Build the structured array for a failed request.
	 *
	 * @param string              $error_code Machine-readable error identifier.
	 * @param array<string,float> $timing     Timing collected so far.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	private function http_failure( string $error_code, array $timing = array() ): array {
		return array(
			'success'    => false,
			'body'       => null,
			'http_code'  => null,
			'timing'     => $timing,
			'error_code' => $error_code,
		);
	}

	/**
	 * Request via curl. Provides detailed timing (DNS/connect/TLS/TTFB/total).
	 *
	 * @param array<string,mixed> $target    The prepared target.
	 * @param int                 $timeout   Timeout in seconds.
	 * @param bool                $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 *
	 * @phpstan-param Http_Target $target
	 */
	private function http_request_curl( array $target, int $timeout, bool $head_only ): array {
		$curl_handle = curl_init( $target['url'] );

		/*
		 * The order matters: curl_setopt_array() stops at the first option
		 * it cannot set. So everything the safety of the request depends on
		 * comes first - and if any option fails, nothing is sent at all.
		 */
		$options = array(
			CURLOPT_FOLLOWLOCATION  => false,
			CURLOPT_PROTOCOLS       => CURLPROTO_HTTP | CURLPROTO_HTTPS,
			CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
		);

		if ( null !== $target['ip'] ) {
			$ip_as_host = str_contains( $target['ip'], ':' ) ? '[' . $target['ip'] . ']' : $target['ip'];

			/*
			 * Pin the connection to the IP the target filter has accepted:
			 * whatever host and port curl reads out of the URL, it connects
			 * to this IP and does not resolve anything. The original host is
			 * still used for the Host header, SNI and the certificate.
			 */
			$options[ CURLOPT_CONNECT_TO ] = array( '::' . $ip_as_host . ':' . $target['port'] );

			/*
			 * curl picks up a proxy from the environment (http_proxy,
			 * https_proxy, ...). A proxy resolves the host on its own, which
			 * would bypass the pinned IP - so with a target filter the
			 * request always goes out directly.
			 */
			$options[ CURLOPT_PROXY ] = '';
		}

		$body      = '';
		$limit     = max( 0, $this->http_max_body_bytes() );
		$truncated = false;

		/*
		 * The body is collected by a callback instead of letting curl return
		 * it, to be able to stop at the limit: returning anything but the
		 * length of the chunk makes curl abort the transfer.
		 */
		$options += array(
			CURLOPT_TIMEOUT        => $timeout,
			CURLOPT_CONNECTTIMEOUT => min( $timeout, 8 ),
			CURLOPT_NOBODY         => $head_only,
			CURLOPT_WRITEFUNCTION  => static function ( $handle, string $chunk ) use ( &$body, &$truncated, $limit ): int {
				$room = $limit - strlen( $body );

				if ( strlen( $chunk ) > $room ) {
					$body     .= substr( $chunk, 0, $room );
					$truncated = true;

					return -1;
				}

				$body .= $chunk;

				return strlen( $chunk );
			},
		);

		if ( ! curl_setopt_array( $curl_handle, $options ) ) {
			curl_close( $curl_handle );

			return $this->http_failure( 'curl_setup_failed' );
		}

		curl_exec( $curl_handle );

		$errno = curl_errno( $curl_handle );

		// A transfer this client has aborted itself at the body limit is no failure.
		if ( 0 !== $errno && ! ( $truncated && CURLE_WRITE_ERROR === $errno ) ) {
			curl_close( $curl_handle );

			return $this->http_failure( 'curl_errno_' . $errno );
		}

		$info = curl_getinfo( $curl_handle );

		// Belt and braces: the peer curl has actually talked to has to be the accepted IP.
		if ( null !== $target['ip'] && inet_pton( (string) $info['primary_ip'] ) !== inet_pton( $target['ip'] ) ) {
			curl_close( $curl_handle );

			return $this->http_failure( 'target_rejected' );
		}

		/*
		 * The TLS handshake time is not part of the curl_getinfo() array, it
		 * has to be requested explicitly. It is 0.0 for an unencrypted
		 * connection, and false if libcurl cannot report it at all.
		 */
		$appconnect_time = curl_getinfo( $curl_handle, CURLINFO_APPCONNECT_TIME );

		curl_close( $curl_handle );

		/*
		 * curl reports every value as the time elapsed since the start of
		 * the request. With a pinned IP the lookup has already happened
		 * before, so its duration is added to keep the values comparable to
		 * a request without a target filter.
		 */
		$offset_ms = $target['resolve_ms'];
		$tls_ms    = (float) $appconnect_time * 1000;

		return array(
			'success'    => true,
			'body'       => $body,
			'http_code'  => (int) $info['http_code'],
			'timing'     => array(
				'dns_ms'     => round( $info['namelookup_time'] * 1000 + $offset_ms, 2 ),
				'connect_ms' => round( $info['connect_time'] * 1000 + $offset_ms, 2 ),
				'tls_ms'     => round( $tls_ms > 0 ? $tls_ms + $offset_ms : 0.0, 2 ),
				'ttfb_ms'    => round( $info['starttransfer_time'] * 1000 + $offset_ms, 2 ),
				'total_ms'   => round( $info['total_time'] * 1000 + $offset_ms, 2 ),
			),
			'error_code' => null,
		);
	}

	/**
	 * Request via a stream context. Fallback if curl is unavailable, only total timing.
	 *
	 * @param array<string,mixed> $target    The prepared target.
	 * @param int                 $timeout   Timeout in seconds.
	 * @param bool                $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 *
	 * @phpstan-param Http_Target $target
	 */
	private function http_request_stream( array $target, int $timeout, bool $head_only ): array {
		$start = microtime( true );

		$http_options = array(
			'method'          => $head_only ? 'HEAD' : 'GET',
			'timeout'         => $timeout,
			// Never follow a redirect, see the class docblock.
			'follow_location' => 0,
			// Return the response of a 4xx/5xx instead of failing, like curl does.
			'ignore_errors'   => true,
		);

		$ssl_options = array();

		if ( null !== $target['ip'] ) {
			/*
			 * Pin the connection to the IP the target filter has accepted:
			 * the URL carries the IP, so nothing is resolved again. The
			 * original host is still sent as Host header, and used for SNI
			 * and for the verification of the certificate. The stream
			 * wrapper never uses a proxy on its own.
			 */
			$default_port           = $target['is_https'] ? 443 : 80;
			$http_options['header'] = 'Host: ' . $target['host'] . ( $default_port === $target['port'] ? '' : ':' . $target['port'] );
			$ssl_options            = array( 'peer_name' => $target['host'] );
		}

		$context = stream_context_create(
			array(
				'http' => $http_options,
				'ssl'  => $ssl_options,
			)
		);

		// Opens the connection and reads the response headers, the body is read below.
		$handle = @fopen( $target['stream_url'], 'rb', false, $context );

		if ( false === $handle ) {
			return $this->http_failure( 'request_failed', array( 'total_ms' => $this->http_stream_elapsed_ms( $start, $target['resolve_ms'] ) ) );
		}

		// The HTTP wrapper provides the response headers as its wrapper data.
		$meta_data        = stream_get_meta_data( $handle );
		$response_headers = isset( $meta_data['wrapper_data'] ) && is_array( $meta_data['wrapper_data'] ) ? $meta_data['wrapper_data'] : array();

		$body       = '';
		$bytes_left = $this->http_max_body_bytes();
		$deadline   = $start + $timeout;
		$timed_out  = false;

		/*
		 * The "timeout" context option only limits every single read, a
		 * server sending a byte every now and then could keep the request
		 * open forever. So the body is read in pieces, against a deadline
		 * for the whole request - and only up to the limit. The body of a
		 * response to a HEAD request is not read, whatever the server sends.
		 */
		while ( ! $head_only && $bytes_left > 0 && ! feof( $handle ) ) {
			$remaining = $deadline - microtime( true );

			if ( $remaining <= 0 ) {
				$timed_out = true;
				break;
			}

			$seconds = (int) $remaining;

			stream_set_timeout( $handle, $seconds, (int) ( ( $remaining - $seconds ) * 1000000 ) );

			$chunk = fread( $handle, min( 8192, $bytes_left ) );

			// A read that ran into the timeout returns false or an empty string, depending on the PHP version.
			if ( false === $chunk || '' === $chunk ) {
				$timed_out = stream_get_meta_data( $handle )['timed_out'];

				if ( $timed_out || false === $chunk ) {
					break;
				}

				continue;
			}

			$body       .= $chunk;
			$bytes_left -= strlen( $chunk );
		}

		fclose( $handle );

		$total_ms = $this->http_stream_elapsed_ms( $start, $target['resolve_ms'] );

		if ( $timed_out ) {
			return $this->http_failure( 'request_failed', array( 'total_ms' => $total_ms ) );
		}

		$status_code = null;

		if ( isset( $response_headers[0] ) && preg_match( '/^HTTP\/\S+\s+(\d{3})\b/', (string) $response_headers[0], $status_matches ) ) {
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

	/**
	 * Return the time a stream request has taken so far.
	 *
	 * @param float $start      Start of the request as a microtime value.
	 * @param float $resolve_ms Time the lookup of the host has taken before, in milliseconds.
	 * @return float Elapsed time in milliseconds, rounded to 2 decimals.
	 */
	private function http_stream_elapsed_ms( float $start, float $resolve_ms ): float {
		return round( ( microtime( true ) - $start ) * 1000 + $resolve_ms, 2 );
	}
}
