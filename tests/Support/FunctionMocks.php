<?php
/**
 * File to hold the registry for namespaced function stubs.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

use Closure;

/**
 * Registry for the namespaced function stubs defined in function_mocks.php.
 *
 * PHP resolves an unqualified function call inside a namespace against that
 * namespace first, and only then against the global scope. The package calls
 * gethostbyname(), fsockopen(), shell_exec() etc. unqualified, so defining
 * same-named functions in TcpAnalyzer\Tests / TcpAnalyzer\Traits lets the
 * tests replace them without touching the production code.
 *
 * Every stub falls back to the native function while no mock is registered,
 * so forgetting a reset() cannot silently break unrelated code.
 */
final class FunctionMocks {

	/**
	 * Namespace of the concrete test classes.
	 *
	 * @var string
	 */
	public const NS_TESTS = 'TcpAnalyzer\\Tests\\';

	/**
	 * Namespace of the traits. Function calls inside a trait are resolved
	 * against the namespace the trait is declared in, not the using class.
	 *
	 * @var string
	 */
	public const NS_TRAITS = 'TcpAnalyzer\\Traits\\';

	/**
	 * Namespace of the traceroute methods.
	 *
	 * @var string
	 */
	public const NS_TRACEROUTE = 'TcpAnalyzer\\Traceroute\\';

	/**
	 * Registered mocks, fully qualified function name => callback.
	 *
	 * @var array<string,Closure>
	 */
	private static array $mocks = array();

	/**
	 * Register a mock for a function in the TcpAnalyzer\Tests namespace.
	 *
	 * @param string  $function Unqualified function name, e.g. "gethostbyname".
	 * @param Closure $callback Replacement callback.
	 * @return void
	 */
	public static function set_for_tests( string $function, Closure $callback ): void {
		self::$mocks[ self::NS_TESTS . $function ] = $callback;
	}

	/**
	 * Register a mock for a function in the TcpAnalyzer\Traits namespace.
	 *
	 * @param string  $function Unqualified function name, e.g. "function_exists".
	 * @param Closure $callback Replacement callback.
	 * @return void
	 */
	public static function set_for_traits( string $function, Closure $callback ): void {
		self::$mocks[ self::NS_TRAITS . $function ] = $callback;
	}

	/**
	 * Register a mock for a function in the TcpAnalyzer\Traceroute namespace.
	 *
	 * @param string  $function Unqualified function name, e.g. "shell_exec".
	 * @param Closure $callback Replacement callback.
	 * @return void
	 */
	public static function set_for_traceroute( string $function, Closure $callback ): void {
		self::$mocks[ self::NS_TRACEROUTE . $function ] = $callback;
	}

	/**
	 * Return the mock registered for a fully qualified function name, if any.
	 *
	 * @param string $function Fully qualified function name.
	 * @return Closure|null
	 */
	public static function get( string $function ): ?Closure {
		return self::$mocks[ $function ] ?? null;
	}

	/**
	 * Remove all registered mocks. Call this in tearDown().
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::$mocks = array();
	}
}
