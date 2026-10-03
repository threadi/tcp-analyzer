<?php
/**
 * File to hold a thin wrapper exposing the Http_Client trait.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use Closure;
use TcpAnalyzer\Traits\Http_Client;

/**
 * Exposes the protected http_request() of the Http_Client trait so the trait
 * can be tested on its own, independent of any concrete test class.
 *
 * The target filter and the name resolution are replaceable, so the pinning
 * can be tested with host names that do not exist in any DNS.
 */
final class Http_Client_Double {

	use Http_Client {
		resolve_target_ips as private native_resolve_target_ips;
		http_max_body_bytes as private native_http_max_body_bytes;
	}

	/**
	 * The target filter to use, null for none.
	 *
	 * @var Closure|null
	 */
	public ?Closure $filter = null;

	/**
	 * Canned name resolution: host => IP family (4 or 6) => addresses.
	 * Hosts not listed here are resolved for real.
	 *
	 * @var array<string,array<int,string[]>>
	 */
	public array $resolves = array();

	/**
	 * Microseconds every name resolution takes, to make it visible in the timing.
	 *
	 * @var int
	 */
	public int $resolve_delay_us = 0;

	/**
	 * Every host/family pair that has been resolved, in order.
	 *
	 * @var array<int,array{host:string,family:int}>
	 */
	public array $resolve_calls = array();

	/**
	 * The body limit to use, null for the default of the trait.
	 *
	 * @var int|null
	 */
	public ?int $max_body_bytes = null;

	/**
	 * Public wrapper around the trait's http_url_without_credentials().
	 *
	 * @param string $url The URL.
	 * @return string
	 */
	public function without_credentials( string $url ): string {
		return $this->http_url_without_credentials( $url );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function http_max_body_bytes(): int {
		return $this->max_body_bytes ?? $this->native_http_max_body_bytes();
	}

	/**
	 * Public wrapper around the trait's http_request().
	 *
	 * @param string $url       The URL to request.
	 * @param int    $timeout   Timeout in seconds.
	 * @param bool   $head_only Whether to send a HEAD-only request.
	 * @return array{success:bool,body:?string,http_code:?int,timing:array<string,float>,error_code:?string}
	 */
	public function request( string $url, int $timeout = 10, bool $head_only = false ): array {
		return $this->http_request( $url, $timeout, $head_only );
	}

	/**
	 * {@inheritDoc}
	 */
	protected function http_target_filter(): ?callable {
		return $this->filter;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function resolve_target_ips( string $host, int $family ): array {
		$this->resolve_calls[] = array(
			'host'   => $host,
			'family' => $family,
		);

		usleep( $this->resolve_delay_us );

		if ( isset( $this->resolves[ $host ] ) ) {
			return $this->resolves[ $host ][ $family ] ?? array();
		}

		return $this->native_resolve_target_ips( $host, $family );
	}
}
