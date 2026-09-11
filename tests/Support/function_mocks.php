<?php
/**
 * File to define namespaced stubs for the native functions the package calls.
 *
 * Each stub delegates to the mock registered in FunctionMocks, or to the
 * native function if none is registered. See FunctionMocks for the why.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\Tests {

	use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;

	/**
	 * Stub for gethostbyname(), used by TcpAnalyzer\Tests\Dns.
	 *
	 * @param string $hostname The hostname to resolve.
	 * @return string
	 */
	function gethostbyname( string $hostname ): string {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? $mock( $hostname ) : \gethostbyname( $hostname );
	}

	/**
	 * Stub for fsockopen(), used by TcpAnalyzer\Tests\TcpConnect.
	 *
	 * @param string      $hostname      The target host.
	 * @param int         $port          The target port.
	 * @param int         $error_code    Error number, by reference.
	 * @param string      $error_message Error message, by reference.
	 * @param float|null  $timeout       Connect timeout in seconds.
	 * @return resource|false
	 */
	function fsockopen( string $hostname, int $port = -1, int &$error_code = 0, string &$error_message = '', ?float $timeout = null ) {
		$mock = FunctionMocks::get( __FUNCTION__ );

		if ( null === $mock ) {
			return \fsockopen( $hostname, $port, $error_code, $error_message, $timeout ?? (float) \ini_get( 'default_socket_timeout' ) );
		}

		return $mock( $hostname, $port, $error_code, $error_message, $timeout );
	}



}

namespace TcpAnalyzer\Traits {

	use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;

	/**
	 * Stub for function_exists(), used by the Http_Client trait to decide
	 * between the curl and the stream implementation.
	 *
	 * @param string $function The function name to check.
	 * @return bool
	 */
	function function_exists( string $function ): bool {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? (bool) $mock( $function ) : \function_exists( $function );
	}
}

namespace TcpAnalyzer\Traceroute {

	use TcpAnalyzer\PHPUnitTests\Support\FunctionMocks;

	/**
	 * Stub for function_exists(), used by Shell_Method.
	 *
	 * @param string $function The function name to check.
	 * @return bool
	 */
	function function_exists( string $function ): bool {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? (bool) $mock( $function ) : \function_exists( $function );
	}

	/**
	 * Stub for ini_get(), used by Shell_Method.
	 *
	 * @param string $option The ini option to read.
	 * @return string|false
	 */
	function ini_get( string $option ) {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? $mock( $option ) : \ini_get( $option );
	}

	/**
	 * Stub for shell_exec(), used by Shell_Method.
	 *
	 * @param string $command The command to run.
	 * @return string|false|null
	 */
	function shell_exec( string $command ) {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? $mock( $command ) : \shell_exec( $command );
	}

	/**
	 * Stub for extension_loaded(), used by Socket_Method.
	 *
	 * @param string $extension The extension name to check.
	 * @return bool
	 */
	function extension_loaded( string $extension ): bool {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? (bool) $mock( $extension ) : \extension_loaded( $extension );
	}

	/**
	 * Stub for socket_create(), used by Socket_Method.
	 *
	 * @param int $domain   Protocol family.
	 * @param int $type     Socket type.
	 * @param int $protocol Protocol number.
	 * @return \Socket|false
	 */
	function socket_create( int $domain, int $type, int $protocol ) {
		$mock = FunctionMocks::get( __FUNCTION__ );

		return null !== $mock ? $mock( $domain, $type, $protocol ) : \socket_create( $domain, $type, $protocol );
	}
}
