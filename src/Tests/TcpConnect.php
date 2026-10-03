<?php
/**
 * File to handle the raw TCP connect test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;
use TcpAnalyzer\Traits\Target_Guard;

/**
 * Opens a raw TCP connection to a host:port and measures the time to connect.
 *
 * Config:
 * - host (string, required): the target host.
 * - port (int, required): the target port, 1 to 65535. Anything else is
 *   refused with the error code "invalid_port".
 * - timeout (int|float): connect timeout in seconds, default 8. A value
 *   that is not positive is replaced by the default.
 * - target_filter (callable): decides whether the host may be connected to,
 *   see Tests_Base::get_target_filter(). With a filter the host is resolved
 *   before the measurement starts, the value is the pure connect time.
 *
 * Result value: connect time in milliseconds on success, null on failure.
 */
class TcpConnect extends Tests_Base {

	use Target_Guard;

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
		$host    = (string) $this->get_scalar_config( 'host', '' );
		$port    = (int) $this->get_scalar_config( 'port', 0 );
		$timeout = (float) $this->get_scalar_config( 'timeout', 8 );

		// Without a positive timeout every failure would be classified as a timeout below.
		if ( $timeout <= 0 ) {
			$timeout = 8.0;
		}

		$errno  = 0;
		$errstr = '';

		// fsockopen() does not refuse a port out of range, it wraps it around: 65616 would connect to port 80.
		if ( $port < 1 || $port > 65535 ) {
			$this->set_result(
				Status::ERROR,
				null,
				array(
					'host' => $host,
					'port' => $port,
				),
				'invalid_port'
			);
			return;
		}

		$connect_to = $host;
		$filter     = $this->get_target_filter();

		if ( null !== $filter ) {
			$target = $this->guard_target( $host, $port, $filter );

			if ( null === $target['ip'] ) {
				$this->set_result(
					Status::ERROR,
					null,
					array(
						'host' => $host,
						'port' => $port,
					),
					$target['error_code']
				);
				return;
			}

			// Connect to the IP the filter has accepted, so fsockopen() does not resolve the host again.
			$connect_to = str_contains( $target['ip'], ':' ) ? '[' . $target['ip'] . ']' : $target['ip'];
		}

		$this->start_timer();
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- fsockopen() warnings are handled via $errno/$errstr on purpose.
		$connection  = @fsockopen( $connect_to, $port, $errno, $errstr, $timeout );
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

		$this->set_result(
			Status::SUCCESS,
			$duration_ms,
			array(
				'host' => $host,
				'port' => $port,
			),
			null,
			$duration_ms
		);
	}
}
