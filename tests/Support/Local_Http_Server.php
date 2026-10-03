<?php
/**
 * File to hold a local HTTP server for the HTTP client tests.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Support;

/**
 * Runs PHP's built-in web server on a free loopback port.
 *
 * What the HTTP client promises - no redirects, no other schemes, a pinned
 * IP - is a property of the real transports, curl and the HTTP stream
 * wrapper. A stub could only repeat what the test already believes, so these
 * tests talk to a real server. It only ever listens on 127.0.0.1.
 */
final class Local_Http_Server {

	/**
	 * The server process.
	 *
	 * @var resource|null
	 */
	private $process = null;

	/**
	 * The port the server listens on.
	 *
	 * @var int
	 */
	private int $port = 0;

	/**
	 * File the router script logs every request to.
	 *
	 * @var string
	 */
	private string $hit_log = '';

	/**
	 * Start the server.
	 *
	 * @return bool False if the server could not be started, e.g. because proc_open() is disabled.
	 */
	public function start(): bool {
		if ( ! function_exists( 'proc_open' ) ) {
			return false;
		}

		$this->port = $this->find_free_port();

		if ( 0 === $this->port ) {
			return false;
		}

		$this->hit_log = (string) tempnam( sys_get_temp_dir(), 'tcp-analyzer-hits-' );
		$null_device   = 'Windows' === PHP_OS_FAMILY ? 'NUL' : '/dev/null';

		$process = proc_open(
			array( PHP_BINARY, '-S', '127.0.0.1:' . $this->port, __DIR__ . '/http_server_router.php' ),
			array(
				0 => array( 'file', $null_device, 'r' ),
				1 => array( 'file', $null_device, 'w' ),
				2 => array( 'file', $null_device, 'w' ),
			),
			$pipes,
			null,
			array_merge( getenv(), array( 'TCP_ANALYZER_HIT_LOG' => $this->hit_log ) )
		);

		if ( ! is_resource( $process ) ) {
			return false;
		}

		$this->process = $process;

		// Wait until the server accepts connections.
		$deadline = microtime( true ) + 5;

		while ( microtime( true ) < $deadline ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors -- a refused connection just means "not ready yet".
			$connection = @fsockopen( '127.0.0.1', $this->port, $errno, $errstr, 0.2 );

			if ( is_resource( $connection ) ) {
				fclose( $connection );

				return true;
			}

			usleep( 20000 );
		}

		$this->stop();

		return false;
	}

	/**
	 * Stop the server and remove the hit log.
	 *
	 * @return void
	 */
	public function stop(): void {
		if ( is_resource( $this->process ) ) {
			proc_terminate( $this->process );
			proc_close( $this->process );
		}

		$this->process = null;

		if ( '' !== $this->hit_log && is_file( $this->hit_log ) ) {
			unlink( $this->hit_log );
		}
	}

	/**
	 * Return the port the server listens on.
	 *
	 * @return int
	 */
	public function get_port(): int {
		return $this->port;
	}

	/**
	 * Build a URL to this server.
	 *
	 * @param string $path Path and query, starting with a slash.
	 * @param string $host Host to use in the URL.
	 * @return string
	 */
	public function url( string $path, string $host = '127.0.0.1' ): string {
		return 'http://' . $host . ':' . $this->port . $path;
	}

	/**
	 * Return the requests the server has seen since the last reset, e.g. "GET /ip".
	 *
	 * @return string[]
	 */
	public function get_hits(): array {
		$content = is_file( $this->hit_log ) ? (string) file_get_contents( $this->hit_log ) : '';

		return '' === trim( $content ) ? array() : explode( "\n", trim( $content ) );
	}

	/**
	 * Forget all requests seen so far.
	 *
	 * @return void
	 */
	public function reset_hits(): void {
		if ( '' !== $this->hit_log ) {
			file_put_contents( $this->hit_log, '' );
		}
	}

	/**
	 * Return a loopback port nothing listens on.
	 *
	 * @return int 0 if none could be determined.
	 */
	public function find_free_port(): int {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- reported via the return value.
		$socket = @stream_socket_server( 'tcp://127.0.0.1:0' );

		if ( ! is_resource( $socket ) ) {
			return 0;
		}

		$name = (string) stream_socket_get_name( $socket, false );

		fclose( $socket );

		return (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );
	}
}
