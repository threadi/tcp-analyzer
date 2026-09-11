<?php
/**
 * File to handle the HTTP request test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;
use TcpAnalyzer\Traits\Http_Client;

/**
 * Sends a HTTP request to a URL and measures DNS/connect/TLS/TTFB/total timing.
 *
 * Config:
 * - url (string, required): the URL to request.
 * - timeout (int): timeout in seconds, default 10.
 * - head_only (bool): send a HEAD-only request, default true.
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
	protected function execute(): void {
		$url      = (string) $this->get_config( 'url' );
		$response = $this->http_request(
			$url,
			(int) $this->get_config( 'timeout', 10 ),
			(bool) $this->get_config( 'head_only', true )
		);

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
