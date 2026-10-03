<?php
/**
 * Router script for the local HTTP server used by the HTTP client tests.
 *
 * Run by PHP's built-in web server, see Local_Http_Server. Every request is
 * appended to the hit log, so a test can prove which requests were made -
 * and, more importantly, which were not.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

$tcp_analyzer_uri  = (string) ( $_SERVER['REQUEST_URI'] ?? '/' );
$tcp_analyzer_path = (string) parse_url( $tcp_analyzer_uri, PHP_URL_PATH );
$tcp_analyzer_log  = (string) getenv( 'TCP_ANALYZER_HIT_LOG' );

if ( '' !== $tcp_analyzer_log ) {
	file_put_contents( $tcp_analyzer_log, ( $_SERVER['REQUEST_METHOD'] ?? '' ) . ' ' . $tcp_analyzer_uri . "\n", FILE_APPEND | LOCK_EX );
}

if ( '/ip' === $tcp_analyzer_path ) {
	echo '203.0.113.42';
	return true;
}

if ( '/internal' === $tcp_analyzer_path ) {
	echo 'internal';
	return true;
}

if ( 1 === preg_match( '#^/status/(\d{3})$#', $tcp_analyzer_path, $tcp_analyzer_matches ) ) {
	http_response_code( (int) $tcp_analyzer_matches[1] );
	echo 'status ' . $tcp_analyzer_matches[1];
	return true;
}

if ( '/redirect' === $tcp_analyzer_path ) {
	header( 'Location: ' . (string) ( $_GET['to'] ?? '/internal' ), true, 302 );
	return true;
}

if ( '/big' === $tcp_analyzer_path ) {
	// A body of the requested size.
	echo str_repeat( 'x', (int) ( $_GET['bytes'] ?? 0 ) );
	return true;
}

if ( '/drip' === $tcp_analyzer_path ) {
	// One byte per second: every single read succeeds in time, the whole response does not.
	while ( ob_get_level() > 0 ) {
		ob_end_flush();
	}

	for ( $tcp_analyzer_second = 0; $tcp_analyzer_second < (int) ( $_GET['seconds'] ?? 0 ); $tcp_analyzer_second++ ) {
		echo 'x';
		flush();
		sleep( 1 );
	}

	return true;
}

if ( '/echo' === $tcp_analyzer_path ) {
	header( 'Content-Type: application/json' );
	echo json_encode(
		array(
			'host' => $_SERVER['HTTP_HOST'] ?? null,
			'uri'  => $tcp_analyzer_uri,
			'user' => $_SERVER['PHP_AUTH_USER'] ?? null,
			'pass' => $_SERVER['PHP_AUTH_PW'] ?? null,
		)
	);
	return true;
}

http_response_code( 404 );
echo 'not found';
return true;
