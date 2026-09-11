<?php
/**
 * File to handle the (best effort) traceroute test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Tests;

use TcpAnalyzer\Enums\Status;
use TcpAnalyzer\Tests_Base;
use TcpAnalyzer\Traceroute\Method_Interface;
use TcpAnalyzer\Traceroute\Shell_Method;
use TcpAnalyzer\Traceroute\Socket_Method;

/**
 * Runs a best-effort traceroute and returns it as structured hop data.
 *
 * The actual work is delegated to a chain of methods (see the
 * TcpAnalyzer\Traceroute namespace): the configured methods are walked in
 * order and the first available one is used. Which method produced the
 * result is reported in the result data.
 *
 * None of them works on a typical shared host - the binary is missing and
 * raw sockets need CAP_NET_RAW - which is reflected via Status::SKIPPED,
 * not as an error. The per-method reason is reported in the result data so
 * the consuming project can tell the user what exactly is missing.
 *
 * Config:
 * - host (string, required): the target host.
 * - max_hops (int): default 20.
 * - wait (int): per-hop wait time in seconds, default 2.
 * - methods (string[]): method slugs to try, in order. Default:
 *   array( 'shell', 'socket' ).
 *
 * Result value: list of hops, each as
 *   array{hop:int, ip:?string, times_ms:float[]}
 * (no text at all - purely numeric/IP data).
 */
class Traceroute extends Tests_Base {

	/**
	 * Available methods, slug => instance.
	 *
	 * @var array<string,Method_Interface>
	 */
	private array $available_methods = array();

	/**
	 * Constructor, registers the built-in methods.
	 */
	public function __construct() {
		$this->register_method( new Shell_Method() );
		$this->register_method( new Socket_Method() );
	}

	/**
	 * Register a custom method, or override a built-in one.
	 *
	 * The method is only used if its slug is listed in the "methods" config.
	 *
	 * @param Method_Interface $method The method to register.
	 * @return void
	 */
	public function register_method( Method_Interface $method ): void {
		$this->available_methods[ $method->get_slug() ] = $method;
	}

	/**
	 * Return all available (built-in + registered) methods.
	 *
	 * @return array<string,Method_Interface>
	 */
	public function get_available_methods(): array {
		return $this->available_methods;
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'traceroute';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_default_config(): array {
		return array(
			'max_hops' => 20,
			'wait'     => 2,
			'methods'  => array( 'shell', 'socket' ),
		);
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
		$host      = (string) $this->get_config( 'host' );
		$max_hops  = (int) $this->get_config( 'max_hops', 20 );
		$wait      = (int) $this->get_config( 'wait', 2 );
		$reasons   = array();
		$attempted = false;

		$this->start_timer();

		foreach ( (array) $this->get_config( 'methods', array() ) as $slug ) {
			$slug = (string) $slug;

			if ( ! isset( $this->available_methods[ $slug ] ) ) {
				$reasons[ $slug ] = 'unknown_method';
				continue;
			}

			$method    = $this->available_methods[ $slug ];
			$unavailable = $method->check_availability();

			if ( null !== $unavailable ) {
				$reasons[ $slug ] = $unavailable;
				continue;
			}

			$attempted = true;
			$hops      = $method->trace( $host, $max_hops, $wait );

			// A method that is available but yields nothing parsable is not a
			// zero-hop success - fall through to the next one.
			if ( empty( $hops ) ) {
				$reasons[ $slug ] = 'traceroute_unavailable';
				continue;
			}

			$this->set_result(
				Status::SUCCESS,
				$hops,
				array(
					'host'      => $host,
					'hop_count' => count( $hops ),
					'method'    => $slug,
				),
				null,
				$this->stop_timer()
			);
			return;
		}

		$this->set_result(
			Status::SKIPPED,
			null,
			array(
				'host'    => $host,
				'methods' => $reasons,
			),
			'traceroute_unavailable',
			$attempted ? $this->stop_timer() : null
		);
	}
}
