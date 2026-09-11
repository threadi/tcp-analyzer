# TCP Analyzer

This repository contains the source code for the Composer package "TCP Analyzer".

## How it works

The package ships a set of independent test classes (`TcpAnalyzer\Tests\*`), each
checking one thing (external IP, DNS resolution, raw TCP connect, HTTP timing,
traceroute). The `TcpAnalyzer` class configures and runs a chosen subset of them.

Every test returns a `TcpAnalyzer\Result` object - a purely structured, language-free
result: a `Status` enum (`success` / `warning` / `error` / `skipped`), the requested
`value` (e.g. the external IP, a millisecond value, a HTTP status code), additional
`data`, and - on failure - a short, stable `error_code` string (e.g.
`tcp_connect_timeout`) instead of an error message. The consuming project maps these
codes to its own text/translations.

Custom tests can be added via `register_test()` as long as they implement
`TcpAnalyzer\Test_Interface` (easiest: extend `TcpAnalyzer\Tests_Base`).

## Requirements

* [_composer_]([composer](https://getcomposer.org/)) to install this package.

## Installation

1. `composer require threadi/tcp-analyzer`
2. Add the following code in your project to run tests:

```php
$tcp_analyzer = new \TcpAnalyzer\TcpAnalyzer();

$tcp_analyzer->set_tests(
	array(
		'external_ip' => array(),
		'dns'         => array( 'host' => 'example.com' ),
		'tcp_connect' => array( 'host' => 'example.com', 'port' => 443 ),
		'http'        => array( 'url' => 'https://example.com' ),
		'traceroute'  => array( 'host' => 'example.com' ),
	)
);

$tcp_analyzer->run();

// Result objects, e.g. $results['dns']->get_status(), ->get_value(), ->get_error_code().
$results = $tcp_analyzer->get_results();

// Or as plain arrays, e.g. for json_encode() / an API response.
$results_as_array = $tcp_analyzer->get_results_as_array();
```

`get_results_as_array()` for the above example looks roughly like this - note
there is no language-specific text anywhere, only stable, machine-readable data:

```json
{
  "external_ip": { "slug": "external_ip", "status": "success", "value": "203.0.113.42", "data": { "provider": "https://api.ipify.org?format=json" }, "error_code": null, "duration_ms": 87.3 },
  "dns":         { "slug": "dns", "status": "success", "value": "93.184.216.34", "data": { "host": "example.com" }, "error_code": null, "duration_ms": 12.1 },
  "tcp_connect": { "slug": "tcp_connect", "status": "error", "value": null, "data": { "host": "example.com", "port": 443, "errno": 0 }, "error_code": "tcp_connect_timeout", "duration_ms": 8000.0 },
  "traceroute":  { "slug": "traceroute", "status": "skipped", "value": null, "data": [], "error_code": "shell_exec_disabled", "duration_ms": null }
}
```

### Parameters

Each test's supported config keys are documented in its class docblock
(`src/Tests/*.php`), e.g. `dns` requires `host`, `tcp_connect` requires `host`
and `port`, `http` requires `url`.

### Adding a custom test

```php
class MyCustomTest extends \TcpAnalyzer\Tests_Base {
	public function get_slug(): string {
		return 'my_custom_test';
	}

	protected function execute(): void {
		// ... do the check, then:
		$this->set_result( \TcpAnalyzer\Enums\Status::SUCCESS, 'some-value' );
	}
}

$tcp_analyzer->register_test( 'my_custom_test', MyCustomTest::class );
$tcp_analyzer->set_tests( array( 'my_custom_test' => array() ) );
```

## For package developers

### Initialize

`composer install`

## Analyze with PHPStan

`vendor/bin/phpstan analyse`
