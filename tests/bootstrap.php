<?php
/**
 * Bootstrap file for the PHPUnit test suite.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

$tcp_analyzer_autoloader = dirname( __DIR__ ) . '/vendor/autoload.php';

if ( ! is_file( $tcp_analyzer_autoloader ) ) {
	fwrite( STDERR, 'Composer autoloader not found. Run "composer install" first.' . PHP_EOL );
	exit( 1 );
}

require_once $tcp_analyzer_autoloader;

/*
 * Namespaced function stubs.
 *
 * Must be loaded explicitly (they are functions, not classes, so the
 * autoloader cannot find them) and before the first call to any of the
 * stubbed functions.
 */
require_once __DIR__ . '/Support/function_mocks.php';
