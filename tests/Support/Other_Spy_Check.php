<?php
/**
 * File to hold a second spying test double with a different slug.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

/**
 * Identical to Spy_Check, but with its own slug, so a run with two
 * registered tests can be told apart in the recorded data.
 */
final class Other_Spy_Check extends Spy_Check {

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'other_spy';
	}
}
