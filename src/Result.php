<?php
/**
 * File to handle a single, structured test result.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer;

use JsonSerializable;
use TcpAnalyzer\Enums\Status;

/**
 * The result of a single test run.
 *
 * This object never carries human-readable sentences. "value" holds the
 * actual, requested measurement (e.g. an IP, a millisecond value, an HTTP
 * status code), "data" holds additional structured context (numbers,
 * codes, nested arrays), and "error_code" - if set - is a short, stable
 * machine identifier (e.g. "tcp_connect_timeout") that the consuming
 * project can map to its own text/translation.
 */
final class Result implements JsonSerializable {

	/**
	 * Constructor.
	 *
	 * @param string      $slug        Slug of the test that produced this result.
	 * @param Status      $status      The resulting status.
	 * @param mixed       $value       The primary, requested value of the test (e.g. the external IP).
	 * @param array<string,mixed>       $data        Additional structured context data (no free text).
	 * @param string|null $error_code  Machine-readable error identifier, if status is not SUCCESS.
	 * @param float|null  $duration_ms Runtime of the test in milliseconds, if measured.
	 */
	public function __construct(
		private readonly string $slug,
		private readonly Status $status,
		private readonly mixed $value = null,
		private readonly array $data = array(),
		private readonly ?string $error_code = null,
		private readonly ?float $duration_ms = null
	) {}

	/**
	 * Return the slug of the test.
	 *
	 * @return string
	 */
	public function get_slug(): string {
		return $this->slug;
	}

	/**
	 * Return the status of the test.
	 *
	 * @return Status
	 */
	public function get_status(): Status {
		return $this->status;
	}

	/**
	 * Return the primary value of the test result.
	 *
	 * @return mixed
	 */
	public function get_value(): mixed {
		return $this->value;
	}

	/**
	 * Return the additional structured data of the test result.
	 *
	 * @return array<string,mixed>
	 */
	public function get_data(): array {
		return $this->data;
	}

	/**
	 * Return the machine-readable error code, if any.
	 *
	 * @return string|null
	 */
	public function get_error_code(): ?string {
		return $this->error_code;
	}

	/**
	 * Return the runtime of the test in milliseconds, if measured.
	 *
	 * @return float|null
	 */
	public function get_duration_ms(): ?float {
		return $this->duration_ms;
	}

	/**
	 * Whether the test finished successfully.
	 *
	 * @return bool
	 */
	public function is_success(): bool {
		return Status::SUCCESS === $this->status;
	}

	/**
	 * Return the result as a plain, array (e.g. for @json_encode()).
	 *
	 * @return array<string,mixed>
	 */
	public function to_array(): array {
		return array(
			'slug'        => $this->slug,
			'status'      => $this->status->value,
			'value'       => $this->value,
			'data'        => $this->data,
			'error_code'  => $this->error_code,
			'duration_ms' => $this->duration_ms,
		);
	}

	/**
	 * JsonSerializable implementation.
	 *
	 * @return array<string,mixed>
	 */
	public function jsonSerialize(): array {
		return $this->to_array();
	}
}
