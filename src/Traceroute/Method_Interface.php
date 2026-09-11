<?php
/**
 * File to define the interface any traceroute method must implement.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Traceroute;

/**
 * Interface any traceroute method must implement.
 *
 * A method is one concrete way to obtain hop data - via an external binary,
 * via raw sockets, or anything a consuming project wants to add. The
 * Traceroute test walks the configured methods in order and uses the first
 * available one.
 */
interface Method_Interface {

	/**
	 * Unique, stable identifier of this method (e.g. "shell").
	 *
	 * Reported in the result data, so it must never change once published.
	 *
	 * @return string
	 */
	public function get_slug(): string;

	/**
	 * Check whether this method can run in the current environment.
	 *
	 * Must be cheap and must not send anything: it is called for every
	 * method before any of them runs.
	 *
	 * @return string|null A machine-readable error code, or null if available.
	 */
	public function check_availability(): ?string;

	/**
	 * Trace the route to a host.
	 *
	 * Implementations must not throw - an unusable result is expressed as an
	 * empty array, which makes the Traceroute test move on to the next
	 * method.
	 *
	 * @param string $host     The target host.
	 * @param int    $max_hops Maximum number of hops to probe.
	 * @param int    $wait     Per-hop wait time in seconds.
	 * @return array<int,array{hop:int,ip:?string,times_ms:float[]}>
	 */
	public function trace( string $host, int $max_hops, int $wait ): array;
}
