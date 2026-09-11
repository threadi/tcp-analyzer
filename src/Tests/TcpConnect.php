<?php
/**
 * File to handle the raw TCP connect test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;

/**
 * Opens a raw TCP connection to a host:port and measures the time to connect.
 *
 * Config:
 * - host (string, required): the target host.
 * - port (int, required): the target port.
 * - timeout (int): connect timeout in seconds, default 8.
 *
 * Result value: connect time in milliseconds on success, null on failure.
 */
class TcpConnect extends Tests_Base {

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'tcp_connect';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_default_config(): array {
		return array( 'timeout' => 8 );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_required_config(): array {
		return array( 'host', 'port' );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function execute(): void {
		$host    = (string) $this->get_config( 'host' );
		$port    = (int) $this->get_config( 'port' );
		$timeout = (float) $this->get_config( 'timeout', 8 );

		$errno  = 0;
		$errstr = '';

		$this->start_timer();
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- fsockopen() warnings are handled via $errno/$errstr on purpose.
		$connection  = @fsockopen( $host, $port, $errno, $errstr, $timeout );
		$duration_ms = $this->stop_timer();

		if ( ! $connection ) {
			// Classified by elapsed time, not by $errno: OS-specific errno values
			// (e.g. ETIMEDOUT) are not portable across platforms, but "connection
			// ran (almost) the full configured timeout" reliably indicates a
			// timeout (firewall/blackhole) vs. an immediate refusal.
			$is_timeout = $duration_ms >= ( $timeout * 1000 * 0.9 );

			// Deliberately not passing $errstr into the result: it is a localized
			// OS error message (free text). $errno is a stable, numeric code.
			$this->set_result(
				Status::ERROR,
				null,
				array(
					'host'  => $host,
					'port'  => $port,
					'errno' => $errno,
				),
				$is_timeout ? 'tcp_connect_timeout' : 'tcp_connect_refused',
				$duration_ms
			);
			return;
		}

		fclose( $connection );

		$this->set_result( Status::SUCCESS, $duration_ms, array( 'host' => $host, 'port' => $port ), null, $duration_ms );
	}
}
