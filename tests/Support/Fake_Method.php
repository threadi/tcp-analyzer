<?php
/**
 * File to hold a fake traceroute method.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use TcpAnalyzer\Traceroute\Method_Interface;

/**
 * A traceroute method with canned answers, used to test the method chain of
 * the Traceroute test without touching a socket or a shell.
 */
final class Fake_Method implements Method_Interface {

	/**
	 * Arguments of every trace() call, in order.
	 *
	 * @var array<int,array{host:string,max_hops:int,wait:int}>
	 */
	public array $calls = array();

	/**
	 * Constructor.
	 *
	 * @param string                                                  $slug         Slug of this method.
	 * @param string|null                                             $availability Error code reported by check_availability().
	 * @param array<int,array{hop:int,ip:?string,times_ms:float[]}>   $hops         Hops returned by trace().
	 */
	public function __construct(
		private readonly string $slug,
		private readonly ?string $availability = null,
		private readonly array $hops = array()
	) {}

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return $this->slug;
	}

	/**
	 * {@inheritDoc}
	 */
	public function check_availability(): ?string {
		return $this->availability;
	}

	/**
	 * {@inheritDoc}
	 */
	public function trace( string $host, int $max_hops, int $wait ): array {
		$this->calls[] = array(
			'host'     => $host,
			'max_hops' => $max_hops,
			'wait'     => $wait,
		);

		return $this->hops;
	}
}
