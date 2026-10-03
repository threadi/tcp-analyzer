# Changelog

## [2.0.0] - 03.10.2026

### Added

- Target filter to restrict, which hosts the tests may talk to, e.g. if a host or URL originates from user input: `TcpAnalyzer::set_target_filter()` resp. the `target_filter` config key of every test
- `Target_Filter::public_only()` as ready-made filter that rejects loopback, private, link-local, carrier-grade NAT and other non-public addresses
- With a target filter the host is resolved once, and the test uses exactly the IP the filter has accepted (protection against DNS rebinding), HTTP requests are pinned to that IP
- New error codes `target_rejected`, `invalid_host`, `invalid_port`, `invalid_url`, `url_scheme_not_allowed` and `curl_setup_failed`; `dns_resolution_failed` is now also used by `tcp_connect`, `http` and `traceroute` if a target filter is set

### Changed

- HTTP requests no longer follow redirects, a 3xx response is reported as it is
- HTTP requests are limited to `http://` and `https://` URLs
- A URL without scheme (e.g. `example.com/path`) is no longer requested, it yields `invalid_url`
- The timeout of an HTTP request is at least 1 second
- The stream fallback of the HTTP client now reports the status code of a 4xx/5xx response instead of failing with `request_failed`, like the curl implementation already did
- Traceroute only accepts a plain hostname or IP address as host
- TCP connect only accepts the ports 1 to 65535
- WordPress Coding Standards compatible, although it could be used elsewhere
- Using PHP strict

### Fixed

- HTTP test could be redirected to internal addresses and thereby reveal internal services and ports (SSRF)
- Stream fallback of the HTTP client could be used to check for the existence of local files via `file://` and other stream wrappers
- Traceroute handed a host starting with a dash to the binary as an option
- TCP connect silently connected to another port if the given one was out of range
- Stream fallback of the HTTP client did not recognize the status code of a response without reason phrase

## [1.0.0] - 11.09.2026

### Added

- Initial Release
