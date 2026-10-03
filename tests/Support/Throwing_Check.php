<?php
/**
 * File to hold a test double that fails in the ways a test must not.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use LogicException;
use TcpAnalyzer\Tests_Base;

/**
 * A test that throws, or returns without a result, depending on its config.
 *
 * Config:
 * - mode (string): "throw" (default) throws, "error" raises a PHP error,
 *   "silent" returns without setting a result.
 */
final class Throwing_Check extends Tests_Base {

	/**
	 * {@inheritDoc}
	 */
	public function get_slug(): string {
		return 'throwing';
	}

	/**
	 * {@inheritDoc}
	 *
	 * @throws LogicException In the "throw" mode.
	 */
	protected function execute(): void {
		$mode = $this->get_config( 'mode', 'throw' );

		if ( 'silent' === $mode ) {
			return;
		}

		if ( 'error' === $mode ) {
			// @phpstan-ignore function.notFound
			\TcpAnalyzer\PHPUnitTests\Support\this_function_does_not_exist();
		}

		throw new LogicException( 'A message that must not show up in any result.' );
	}
}
