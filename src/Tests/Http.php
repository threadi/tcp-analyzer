<?php
/**
 * File to handle the HTTP request test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;
use TcpAnalyzer\Traits\Http_Client;

/**
 * Sends an HTTP request to a URL and measures DNS/connect/TLS/TTFB/total timing.
 *
 * Config:
 * - url (string, required): the URL to request.
 * - timeout (int): timeout in seconds, default 10.
 * - head_only (bool): send a HEAD-only request, default true.
 * - target_filter (callable): decides whether the host of the URL may be
 *   requested, see Tests_Base::get_target_filter().
 *
 * Only http:// and https:// URLs are requested, and redirects are not
 * followed: the result describes the given URL, a 3xx status is reported
 * as it is (and counts as success).
 *
 * Not more than 1 MB of a response body is read, and credentials given in
 * the URL are not repeated in the result data.
 *
 * Result value: the HTTP status code on success, null on failure.
 * Result data: 'timing' with dns_ms/connect_ms/tls_ms/ttfb_ms/total_ms
 * (dns_ms/connect_ms/tls_ms/ttfb_ms only available when curl is used).
 */
class Http extends Tests_Base {

	use Http_Client;

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'http';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_default_config(): array {
		return array(
			'timeout'   => 10,
			'head_only' => true,
		);
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_required_config(): array {
		return array( 'url' );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function http_target_filter(): ?callable {
		return $this->get_target_filter();
	}

	/**
	 * {@inheritDoc}
	 */
	protected function execute(): void {
		$url      = (string) $this->get_scalar_config( 'url', '' );
		$response = $this->http_request(
			$url,
			(int) $this->get_scalar_config( 'timeout', 10 ),
			(bool) $this->get_scalar_config( 'head_only', true )
		);

		// Credentials are needed for the request, but have no place in the result.
		$url = $this->http_url_without_credentials( $url );

		if ( ! $response['success'] ) {
			$this->set_result(
				Status::ERROR,
				null,
				array(
					'url'    => $url,
					'timing' => $response['timing'],
				),
				$response['error_code'] ?? 'http_request_failed',
				$response['timing']['total_ms'] ?? null
			);
			return;
		}

		$http_code = $response['http_code'];
		$status    = ( null !== $http_code && $http_code >= 200 && $http_code < 400 ) ? Status::SUCCESS : Status::WARNING;

		$this->set_result(
			$status,
			$http_code,
			array(
				'url'    => $url,
				'timing' => $response['timing'],
			),
			Status::SUCCESS === $status ? null : 'http_status_not_ok',
			$response['timing']['total_ms'] ?? null
		);
	}
}
