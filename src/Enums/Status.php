<?php
/**
 * File to hold the possible result states of a test.
 *
 * @package tcp-analyzer
 */

namespace TcpAnalyzer\Enums;

/**
 * The possible states a test result can have.
 *
 * This is intentionally a closed, machine-readable set (no free text) so
 * that any consuming project can safely switch on it without depending on
 * a specific language.
 */
enum Status: string {
	case SUCCESS = 'success';
	case WARNING = 'warning';
	case ERROR   = 'error';
	case SKIPPED = 'skipped';
}
