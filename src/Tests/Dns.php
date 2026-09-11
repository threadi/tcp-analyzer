<?php
/**
 * File to handle the DNS resolution test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;

/**
 * Resolves a hostname to an IP address.
 *
 * Config:
 * - host (string, required): the hostname to resolve.
 *
 * Result value: the resolved IP as string, or null on failure.
 */
class Dns extends Tests_Base {

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'dns';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_required_config(): array {
		return array( 'host' );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function execute(): void {
		$host = (string) $this->get_config( 'host' );

		$this->start_timer();
		$resolved_ip = gethostbyname( $host );
		$duration_ms = $this->stop_timer();

		if ( $resolved_ip === $host ) {
			$this->set_result( Status::ERROR, null, array( 'host' => $host ), 'dns_resolution_failed', $duration_ms );
			return;
		}

		$this->set_result( Status::SUCCESS, $resolved_ip, array( 'host' => $host ), null, $duration_ms );
	}
}
