<?php
/**
 * File to provide the target check shared by all tests that open a connection.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Traits;

use TcpAnalyzer\Target_Filter;

/**
 * Resolves a host exactly once and asks a filter whether the resulting
 * address may be used.
 *
 * The point of doing both in one place: the address the filter has seen is
 * the address the test then connects to. A test that lets fsockopen() or
 * curl resolve the name a second time can be handed a different address on
 * that second lookup (DNS rebinding), which would make any check done on
 * the first one worthless.
 */
trait Target_Guard {

	/**
	 * Resolve a host and return the first address the filter accepts.
	 *
	 * IPv4 addresses are tried first. IPv6 is only looked up if no IPv4
	 * address was found or accepted.
	 *
	 * The filter is called as $filter( string $host, string $ip, ?int $port )
	 * and has to return exactly true to accept the address - anything else
	 * rejects it.
	 *
	 * @param string   $host   The host as configured: a name or an IP address.
	 * @param int|null $port   The port the test will connect to, null if it has none.
	 * @param callable $filter The target filter.
	 * @return array{ip:?string,error_code:?string,resolve_ms:float} The accepted IP, or an error code:
	 *                                                               "invalid_host", "dns_resolution_failed"
	 *                                                               or "target_rejected".
	 */
	protected function guard_target( string $host, ?int $port, callable $filter ): array {
		$start = microtime( true );

		if ( ! Target_Filter::is_valid_host( $host ) ) {
			return array(
				'ip'         => null,
				'error_code' => 'invalid_host',
				'resolve_ms' => 0.0,
			);
		}

		$resolved_any = false;

		foreach ( array( 4, 6 ) as $family ) {
			foreach ( $this->resolve_target_ips( $host, $family ) as $ip ) {
				$resolved_any = true;

				if ( true === $filter( $host, $ip, $port ) ) {
					return array(
						'ip'         => $ip,
						'error_code' => null,
						'resolve_ms' => round( ( microtime( true ) - $start ) * 1000, 2 ),
					);
				}
			}
		}

		return array(
			'ip'         => null,
			'error_code' => $resolved_any ? 'target_rejected' : 'dns_resolution_failed',
			'resolve_ms' => round( ( microtime( true ) - $start ) * 1000, 2 ),
		);
	}

	/**
	 * Resolve a host to its addresses of one IP family.
	 *
	 * An IP address is returned as it is (without brackets), if it belongs
	 * to the requested family.
	 *
	 * @param string $host   The host: a name or an IP address.
	 * @param int    $family 4 or 6.
	 * @return string[]
	 */
	protected function resolve_target_ips( string $host, int $family ): array {
		$literal = ( str_starts_with( $host, '[' ) && str_ends_with( $host, ']' ) ) ? substr( $host, 1, -1 ) : $host;

		if ( false !== filter_var( $literal, FILTER_VALIDATE_IP ) ) {
			$is_ipv6 = str_contains( $literal, ':' );

			return ( 6 === $family ) === $is_ipv6 ? array( $literal ) : array();
		}

		if ( 4 === $family ) {
			$addresses = gethostbynamel( $host );

			return is_array( $addresses ) ? $addresses : array();
		}

		if ( ! function_exists( 'dns_get_record' ) ) {
			return array();
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- a failed lookup is reported as "no address", not as a warning.
		$records = @dns_get_record( $host, DNS_AAAA );

		if ( ! is_array( $records ) ) {
			return array();
		}

		$addresses = array();

		foreach ( $records as $record ) {
			if ( isset( $record['ipv6'] ) && is_string( $record['ipv6'] ) ) {
				$addresses[] = $record['ipv6'];
			}
		}

		return $addresses;
	}
}
