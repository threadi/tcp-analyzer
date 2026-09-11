<?php
/**
 * File to handle the traceroute method using an external binary.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Traceroute;

/**
 * Runs the traceroute binary via shell_exec() and parses its output.
 *
 * Requires shell_exec() to be enabled and the binary to be installed and
 * permitted - which is usually NOT the case on shared hosting.
 */
class Shell_Method implements Method_Interface {

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'shell';
	}

	/**
	 * {@inheritDoc}
	 */
	public function check_availability(): ?string {
		if ( ! function_exists( 'shell_exec' ) ) {
			return 'shell_exec_unavailable';
		}

		$disabled_functions = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );

		if ( in_array( 'shell_exec', $disabled_functions, true ) ) {
			return 'shell_exec_disabled';
		}

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public function trace( string $host, int $max_hops, int $wait ): array {
		$command = sprintf( 'traceroute -n -w %d -m %d %s 2>&1', $wait, $max_hops, escapeshellarg( $host ) );

		// phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.PHP.DiscouragedPHPFunctions -- best-effort diagnostic tool, output is discarded on failure.
		$output = @shell_exec( $command );

		if ( empty( $output ) ) {
			return array();
		}

		return $this->parse_hops( (string) $output );
	}

	/**
	 * Parse raw traceroute output into structured hop data.
	 *
	 * Output that yields no parsable hop - e.g. "command not found" from the
	 * shell - returns an empty array, so the caller can tell it apart from a
	 * genuine zero-hop result.
	 *
	 * @param string $output Raw command output.
	 * @return array<int,array{hop:int,ip:?string,times_ms:float[]}>
	 */
	private function parse_hops( string $output ): array {
		$hops = array();

		foreach ( explode( "\n", trim( $output ) ) as $line ) {
			if ( ! preg_match( '/^\s*(\d+)\s+(.*)$/', $line, $line_matches ) ) {
				continue;
			}

			$rest = $line_matches[2];

			preg_match( '/\d{1,3}(?:\.\d{1,3}){3}/', $rest, $ip_matches );
			preg_match_all( '/([\d.]+)\s*ms/', $rest, $time_matches );

			$hops[] = array(
				'hop'      => (int) $line_matches[1],
				'ip'       => $ip_matches[0] ?? null,
				'times_ms' => array_map( 'floatval', $time_matches[1] ),
			);
		}

		return $hops;
	}
}
