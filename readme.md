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

### Restricting targets

The package does not restrict what a test may talk to - checking an internal
host is a legitimate use of a diagnostic tool. As soon as a host or URL
originates from **user input**, though, the tests could be abused to probe
the internal network of the server (SSRF): which hosts exist, which ports are
open, what the cloud metadata service answers. In that case set a target
filter:

```php
$tcp_analyzer = new \TcpAnalyzer\TcpAnalyzer();

// Only publicly routable addresses: no loopback, private, link-local
// (169.254.169.254), carrier-grade NAT (100.64.0.0/10), ... - IPv4 and IPv6.
$tcp_analyzer->set_target_filter( \TcpAnalyzer\Target_Filter::public_only() );
```

The filter is any callable. It is asked with the configured host, the IP that
host resolved to and the port (`null` for tests without one), and has to
return exactly `true` to accept the target:

```php
$tcp_analyzer->set_target_filter(
	static function ( string $host, string $ip, ?int $port ): bool {
		return \TcpAnalyzer\Target_Filter::is_public_ip( $ip ) && in_array( $port, array( 80, 443, null ), true );
	}
);
```

What a filter guarantees:

* The host is resolved **once**. The IP the filter has accepted is the IP the
  test connects to (`tcp_connect`, `traceroute`) resp. the IP the HTTP
  request is pinned to (`http`, `external_ip`) - a second DNS answer cannot
  redirect the test somewhere else (DNS rebinding). `dns` does not report an
  IP the filter has rejected.
* A rejected target yields the error code `target_rejected`, a host that does
  not resolve `dns_resolution_failed`, and a host that is neither a plain
  ASCII hostname nor an IP address in its usual notation `invalid_host`
  (internationalized names have to be given as punycode; `2130706433`,
  `127.1` or `0x7f000001` are refused).
* With a filter, an HTTP request never uses a proxy (curl would otherwise
  pick one up from the environment), as a proxy resolves the host on its own.

A filter can also be set for a single test via its `target_filter` config
key, which takes precedence over the one of the analyzer (`null` opts that
test out). So never build the config of a test from user input as a whole,
only pass on the single values.

One thing a filter cannot hide: `target_rejected` and `dns_resolution_failed`
are different answers, so they still tell whether a name exists in the
internal DNS. Show both as the same message if that matters to you.

Independent of any filter, the HTTP based tests (`http`, `external_ip`):

* only request `http://` and `https://` URLs - anything else yields
  `url_scheme_not_allowed`, an incomplete URL (no scheme, no host, port 0,
  whitespace) `invalid_url`;
* never follow redirects. The result describes the URL that was given: a
  `301` is reported as `301` (and counts as success), the redirect target is
  not requested;
* read not more than 1 MB of a response body, the rest is cut off;
* treat the timeout as the limit for the whole request. One exception: the
  stream fallback (used if curl is missing) cannot limit the time a server
  takes to send its response headers as a whole, only every single read;
* do not repeat credentials given in the URL (`https://user:pass@...`) in the
  result data.

`traceroute` only accepts a plain hostname or IP address as host, anything
else yields `invalid_host`. `tcp_connect` only accepts the ports 1 to 65535,
anything else yields `invalid_port`.

### Limits and failures

The tests are built to end in reasonable time, and a failing test does not
take the others down:

* `traceroute` limits `max_hops` to 1 to 64 and `wait` to 1 to 10 seconds.
  The built-in socket method additionally stops after 30 seconds and reports
  the hops found until then (the second constructor argument of
  `Socket_Method` sets another budget). The shell method runs as long as the
  `traceroute` binary does.
* A required config value that is not a string, number or boolean yields
  `invalid_config`, an optional one of the wrong type falls back to its
  default.
* A test that throws - a custom test, a target filter - does not stop the
  run: it is reported with the error code `test_exception` and the class of
  what has been thrown in `data.exception`, the other tests still run.

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
