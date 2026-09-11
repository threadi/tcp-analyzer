<?php
/**
 * File to test the Status enum.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Enums\Status;

/**
 * Tests for TcpAnalyzer\Enums\Status.
 *
 * The string values are part of the public contract - consuming projects map
 * them to their own translations, so a rename would be a breaking change.
 */
#[CoversClass( Status::class )]
final class Status_Test extends TestCase {

	/**
	 * The set of cases and their backing values is closed and stable.
	 *
	 * @return void
	 */
	#[Test]
	public function provides_exactly_the_documented_cases(): void {
		$values = array_map( static fn( Status $status ): string => $status->value, Status::cases() );

		$this->assertSame( array( 'success', 'warning', 'error', 'skipped' ), $values );
	}

	/**
	 * Values can be restored from their string representation.
	 *
	 * @return void
	 */
	#[Test]
	public function can_be_restored_from_its_string_value(): void {
		$this->assertSame( Status::SUCCESS, Status::from( 'success' ) );
		$this->assertSame( Status::WARNING, Status::from( 'warning' ) );
		$this->assertSame( Status::ERROR, Status::from( 'error' ) );
		$this->assertSame( Status::SKIPPED, Status::from( 'skipped' ) );
	}

	/**
	 * Unknown values do not silently map to a case.
	 *
	 * @return void
	 */
	#[Test]
	public function returns_null_for_unknown_values(): void {
		$this->assertNull( Status::tryFrom( 'unknown' ) );
		$this->assertNull( Status::tryFrom( 'SUCCESS' ) );
		$this->assertNull( Status::tryFrom( '' ) );
	}
}
