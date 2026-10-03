<?php
/**
 * File to handle the external IP test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;
use TcpAnalyzer\Traits\Http_Client;

/**
 * Determines the external (public) IP address of the current server.
 *
 * Config:
 * - providers (string[]): list of URLs to try, in order. Each may return
 *   either a JSON body with an "ip" key or the plain IP as body.
 * - timeout (int): timeout in seconds per provider.
 * - target_filter (callable): decides whether the host of a provider may be
 *   requested, see Tests_Base::get_target_filter(). A rejected provider is
 *   skipped.
 *
 * Result value: the external IP as string, or null on failure.
 */
class ExternalIp extends Tests_Base {

	use Http_Client;

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'external_ip';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_default_config(): array {
		return array(
			'providers' => array(
				'https://api.ipify.org?format=json',
				'https://ifconfig.me/ip',
				'https://icanhazip.com',
			),
			'timeout'   => 5,
		);
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
		$this->start_timer();

		foreach ( (array) $this->get_config( 'providers' ) as $provider_url ) {
			// Anything but a URL in the list is skipped like a provider that does not answer.
			if ( ! is_string( $provider_url ) ) {
				continue;
			}

			$ip = $this->request_ip( $provider_url, (int) $this->get_scalar_config( 'timeout', 5 ) );

			if ( null !== $ip ) {
				$this->set_result( Status::SUCCESS, $ip, array( 'provider' => $this->http_url_without_credentials( $provider_url ) ), null, $this->stop_timer() );
				return;
			}
		}

		$this->set_result( Status::ERROR, null, array(), 'external_ip_unavailable', $this->stop_timer() );
	}

	/**
	 * Try to get a valid IP from a single provider.
	 *
	 * @param string $url     Provider URL.
	 * @param int    $timeout Timeout in seconds.
	 * @return string|null
	 */
	private function request_ip( string $url, int $timeout ): ?string {
		$response = $this->http_request( $url, $timeout );

		if ( ! $response['success'] || null === $response['body'] ) {
			return null;
		}

		$body      = trim( $response['body'] );
		$decoded   = json_decode( $body, true );
		$candidate = is_array( $decoded ) && isset( $decoded['ip'] ) ? (string) $decoded['ip'] : $body;
		$candidate = trim( $candidate );

		return filter_var( $candidate, FILTER_VALIDATE_IP ) ? $candidate : null;
	}
}
