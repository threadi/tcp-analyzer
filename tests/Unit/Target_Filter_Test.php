<?php
/**
 * File to test the target filter helpers.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer\PHPUnitTests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TcpAnalyzer\Target_Filter;

/**
 * Tests for TcpAnalyzer\Target_Filter.
 */
#[CoversClass( Target_Filter::class )]
final class Target_Filter_Test extends TestCase {

	/**
	 * Publicly routable addresses are accepted.
	 *
	 * @param string $ip The IP address to check.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_public_ips' )]
	public function accepts_a_public_ip( string $ip ): void {
		$this->assertTrue( Target_Filter::is_public_ip( $ip ) );
	}

	/**
	 * Data provider: publicly routable addresses, incl. the neighbours of
	 * the non-public ranges.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_public_ips(): array {
		$ips = array(
			'1.1.1.1',
			'8.8.8.8',
			'9.255.255.255',
			'11.0.0.0',
			'93.184.216.34',
			'100.63.255.255',
			'100.128.0.0',
			'126.255.255.255',
			'128.0.0.0',
			'169.253.255.255',
			'169.255.0.0',
			'172.15.255.255',
			'172.32.0.0',
			'192.167.255.255',
			'192.169.0.0',
			'198.17.255.255',
			'198.20.0.0',
			'223.255.255.255',
			'2606:4700:4700::1111',
			'2001:4860:4860::8888',
			'2a00:1450:4001:81b::200e',
			'3ffe::1',
			// Wrapped public IPv4 addresses.
			'::ffff:8.8.8.8',
			'64:ff9b::808:808',
			'2002:808:808::1',
		);

		return array_combine( $ips, array_map( static fn( string $ip ): array => array( $ip ), $ips ) );
	}

	/**
	 * Everything that is not publicly routable is rejected.
	 *
	 * @param string $ip The IP address to check.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_non_public_ips' )]
	public function rejects_a_non_public_ip( string $ip ): void {
		$this->assertFalse( Target_Filter::is_public_ip( $ip ) );
	}

	/**
	 * Data provider: addresses that are not publicly routable.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_non_public_ips(): array {
		return array(
			'this network'                 => array( '0.0.0.0' ),
			'private 10/8, first'          => array( '10.0.0.0' ),
			'private 10/8, last'           => array( '10.255.255.255' ),
			'carrier-grade NAT, first'     => array( '100.64.0.0' ),
			'carrier-grade NAT'            => array( '100.64.0.1' ),
			'carrier-grade NAT, last'      => array( '100.127.255.255' ),
			'loopback'                     => array( '127.0.0.1' ),
			'loopback, last'               => array( '127.255.255.255' ),
			'cloud metadata'               => array( '169.254.169.254' ),
			'link-local'                   => array( '169.254.0.1' ),
			'private 172.16/12, first'     => array( '172.16.0.0' ),
			'private 172.16/12, last'      => array( '172.31.255.255' ),
			'IETF protocol assignments'    => array( '192.0.0.1' ),
			'documentation 192.0.2/24'     => array( '192.0.2.1' ),
			'6to4 relay anycast'           => array( '192.88.99.1' ),
			'private 192.168/16'           => array( '192.168.1.1' ),
			'benchmarking, first'          => array( '198.18.0.0' ),
			'benchmarking, last'           => array( '198.19.255.255' ),
			'documentation 198.51.100/24'  => array( '198.51.100.7' ),
			'documentation 203.0.113/24'   => array( '203.0.113.42' ),
			'multicast, first'             => array( '224.0.0.0' ),
			'multicast, last'              => array( '239.255.255.255' ),
			'reserved'                     => array( '240.0.0.1' ),
			'broadcast'                    => array( '255.255.255.255' ),
			'IPv6 unspecified'             => array( '::' ),
			'IPv6 loopback'                => array( '::1' ),
			'IPv4-compatible loopback'     => array( '::127.0.0.1' ),
			'IPv4-mapped loopback'         => array( '::ffff:127.0.0.1' ),
			'IPv4-mapped private'          => array( '::ffff:10.0.0.1' ),
			'IPv4-mapped metadata'         => array( '::ffff:169.254.169.254' ),
			'NAT64 private'                => array( '64:ff9b::a00:1' ),
			'NAT64 loopback'               => array( '64:ff9b::7f00:1' ),
			'NAT64 local-use'              => array( '64:ff9b:1::1' ),
			'discard-only'                 => array( '100::1' ),
			'Teredo'                       => array( '2001::1' ),
			'documentation 2001:db8::/32'  => array( '2001:db8::1' ),
			'6to4 loopback'                => array( '2002:7f00:1::1' ),
			'6to4 private'                 => array( '2002:c0a8:101::1' ),
			'documentation 3fff::/20'      => array( '3fff::1' ),
			'unallocated'                  => array( '4000::1' ),
			'unique local fc00::/8'        => array( 'fc00::1' ),
			'unique local fd00::/8'        => array( 'fd12:3456:789a::1' ),
			'link-local IPv6'              => array( 'fe80::1' ),
			'site-local, deprecated'       => array( 'fec0::1' ),
			'multicast IPv6'               => array( 'ff02::1' ),
			'not an IP'                    => array( 'example.com' ),
			'empty'                        => array( '' ),
			'short notation'               => array( '127.1' ),
			'decimal notation'             => array( '2130706433' ),
			'bracketed'                    => array( '[2606:4700:4700::1111]' ),
			'with port'                    => array( '8.8.8.8:80' ),
			'trailing whitespace'          => array( '8.8.8.8 ' ),
			'trailing line break'          => array( "8.8.8.8\n" ),
		);
	}

	/**
	 * The ready-made filter decides by the IP alone, whatever the host
	 * name says.
	 *
	 * @return void
	 */
	#[Test]
	public function provides_a_filter_for_public_targets(): void {
		$filter = Target_Filter::public_only();

		$this->assertTrue( $filter( 'example.com', '93.184.216.34', 443 ) );
		$this->assertTrue( $filter( 'example.com', '2606:4700:4700::1111', null ) );
		$this->assertFalse( $filter( 'example.com', '127.0.0.1', 443 ) );
		$this->assertFalse( $filter( '93.184.216.34', '10.0.0.1', 80 ) );
		$this->assertFalse( $filter( 'metadata.internal', '169.254.169.254', 80 ) );
	}

	/**
	 * Plain hostnames and IP addresses are valid hosts.
	 *
	 * @param string $host The host to check.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_valid_hosts' )]
	public function accepts_a_plain_host( string $host ): void {
		$this->assertTrue( Target_Filter::is_valid_host( $host ) );
	}

	/**
	 * Data provider: valid hosts.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_valid_hosts(): array {
		return array(
			'hostname'              => array( 'example.com' ),
			'single label'          => array( 'localhost' ),
			'fully qualified'       => array( 'example.com.' ),
			'with dash'             => array( 'my-host.example.com' ),
			'with underscore'       => array( 'my_service' ),
			'leading digit'         => array( '1und1.de' ),
			'numeric label'         => array( '123.example.com' ),
			'hex-like label'        => array( '0x7f.example.com' ),
			'label ending in digit' => array( 'host1' ),
			'hex-like, but a name'  => array( '0xyz' ),
			'punycode'              => array( 'xn--mnchen-3ya.de' ),
			'upper case'            => array( 'EXAMPLE.COM' ),
			'IPv4'                  => array( '93.184.216.34' ),
			'IPv6'                  => array( '2001:db8::1' ),
			'IPv6 in brackets'      => array( '[2001:db8::1]' ),
			'longest possible name' => array( str_repeat( 'a', 253 ) ),
		);
	}

	/**
	 * Everything else is not a valid host - most notably anything a command
	 * line tool would read as an option.
	 *
	 * @param string $host The host to check.
	 * @return void
	 */
	#[Test]
	#[DataProvider( 'provide_invalid_hosts' )]
	public function rejects_a_host_that_is_not_plain( string $host ): void {
		$this->assertFalse( Target_Filter::is_valid_host( $host ) );
	}

	/**
	 * Data provider: invalid hosts.
	 *
	 * @return array<string,array{string}>
	 */
	public static function provide_invalid_hosts(): array {
		return array(
			'empty'                 => array( '' ),
			'short option'          => array( '-i' ),
			'long option'           => array( '--help' ),
			'leading dot'           => array( '.example.com' ),
			'whitespace'            => array( 'example.com -i' ),
			'leading whitespace'    => array( ' example.com' ),
			'trailing line break'   => array( "example.com\n" ),
			'second line'           => array( "example.com\n-i" ),
			'null byte'             => array( "example.com\0" ),
			'shell metacharacters'  => array( 'example.com; id' ),
			'command substitution'  => array( '$(id)' ),
			'path'                  => array( 'example.com/path' ),
			'port'                  => array( 'example.com:443' ),
			'userinfo'              => array( 'user@example.com' ),
			'fragment trick'        => array( 'example.com#@internal' ),
			'backslash'             => array( 'example.com\\@internal' ),
			'percent-encoded'       => array( 'ex%61mple.com' ),
			'scheme'                => array( 'ssl://example.com' ),
			'unix socket'           => array( 'unix:///var/run/docker.sock' ),
			'unicode'               => array( 'münchen.de' ),
			'IPv4 in brackets'      => array( '[127.0.0.1]' ),
			'unbalanced bracket'    => array( '[2001:db8::1' ),
			'too long'              => array( str_repeat( 'a', 254 ) ),
			'decimal IPv4'          => array( '2130706433' ),
			'short IPv4'            => array( '127.1' ),
			'octal IPv4'            => array( '017700000001' ),
			'hex IPv4'              => array( '0x7f000001' ),
			'hex IPv4, upper case'  => array( '0X7F000001' ),
			'hex IPv4, dotted'      => array( '0x7f.1' ),
			'mixed IPv4'            => array( '127.0x0.0.1' ),
			'hex metadata address'  => array( '0xa9fea9fe' ),
			'numeric, trailing dot' => array( '2130706433.' ),
			'IPv4 with 5 parts'     => array( '1.2.3.4.5' ),
		);
	}
}
