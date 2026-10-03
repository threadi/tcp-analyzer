<?php
/**
 * File to provide helpers to validate the target of a test.
 *
 * @package tcp-analyzer
 */

declare(strict_types=1);

namespace TcpAnalyzer;

use Closure;

/**
 * Helpers to decide whether a test may talk to a given target.
 *
 * The package itself does not restrict targets - checking internal hosts is
 * a legitimate use of a diagnostic tool. A consuming project that passes on
 * user input must restrict them via the "target_filter" config option, see
 * the readme. public_only() is a ready-made filter for that.
 */
final class Target_Filter {

	/**
	 * Return a target filter that only accepts publicly routable addresses.
	 *
	 * @return Closure(string, string, ?int): bool
	 */
	public static function public_only(): Closure {
		// Host and port do not matter here, so the port is not even declared.
		return static fn( string $host, string $ip ): bool => self::is_public_ip( $ip );
	}

	/**
	 * IPv4 ranges that are not publicly routable, see the IANA IPv4 special-purpose address registry.
	 *
	 * @var string[]
	 */
	private const NON_PUBLIC_IPV4 = array(
		'0.0.0.0/8',       // "This network".
		'10.0.0.0/8',      // Private.
		'100.64.0.0/10',   // Carrier-grade NAT.
		'127.0.0.0/8',     // Loopback.
		'169.254.0.0/16',  // Link-local, incl. the cloud metadata address 169.254.169.254.
		'172.16.0.0/12',   // Private.
		'192.0.0.0/24',    // IETF protocol assignments.
		'192.0.2.0/24',    // Documentation.
		'192.88.99.0/24',  // Former 6to4 relay anycast.
		'192.168.0.0/16',  // Private.
		'198.18.0.0/15',   // Benchmarking.
		'198.51.100.0/24', // Documentation.
		'203.0.113.0/24',  // Documentation.
		'224.0.0.0/4',     // Multicast.
		'240.0.0.0/4',     // Reserved, incl. the broadcast address.
	);

	/**
	 * IPv6 ranges inside the global unicast space (2000::/3) that are not
	 * publicly routable, see the IANA IPv6 special-purpose address registry.
	 * Everything outside 2000::/3 is not public anyway.
	 *
	 * @var string[]
	 */
	private const NON_PUBLIC_IPV6 = array(
		'2001::/23',     // IETF protocol assignments, incl. Teredo.
		'2001:db8::/32', // Documentation.
		'3fff::/20',     // Documentation.
	);

	/**
	 * Check whether an IP address is publicly routable.
	 *
	 * Rejects loopback, private, link-local (incl. the cloud metadata
	 * address 169.254.169.254), carrier-grade NAT (100.64.0.0/10), reserved,
	 * documentation and multicast ranges, for IPv4 and IPv6. Addresses that
	 * merely wrap an IPv4 address (IPv4-mapped, NAT64, 6to4) are judged by
	 * the address they wrap.
	 *
	 * @param string $ip The IP address to check.
	 * @return bool
	 */
	public static function is_public_ip( string $ip ): bool {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return false;
		}

		if ( 4 === strlen( $packed ) ) {
			return ! self::is_in_ranges( $packed, self::NON_PUBLIC_IPV4 );
		}

		$embedded_ipv4 = null;

		if ( self::is_in_ranges( $packed, array( '::ffff:0:0/96', '64:ff9b::/96' ) ) ) {
			// IPv4-mapped and NAT64: the IPv4 address is in the last 4 bytes.
			$embedded_ipv4 = substr( $packed, 12, 4 );
		} elseif ( self::is_in_ranges( $packed, array( '2002::/16' ) ) ) {
			// 6to4: the IPv4 address follows the prefix.
			$embedded_ipv4 = substr( $packed, 2, 4 );
		}

		if ( null !== $embedded_ipv4 ) {
			return ! self::is_in_ranges( $embedded_ipv4, self::NON_PUBLIC_IPV4 );
		}

		return self::is_in_ranges( $packed, array( '2000::/3' ) ) && ! self::is_in_ranges( $packed, self::NON_PUBLIC_IPV6 );
	}

	/**
	 * Check whether a packed IP address lies in one of the given CIDR ranges.
	 *
	 * @param string   $packed The address in its packed form, see inet_pton().
	 * @param string[] $ranges CIDR ranges of the same IP family.
	 * @return bool
	 */
	private static function is_in_ranges( string $packed, array $ranges ): bool {
		foreach ( $ranges as $range ) {
			list( $network, $prefix_length ) = explode( '/', $range );

			$packed_network = inet_pton( $network );

			if ( false === $packed_network || strlen( $packed_network ) !== strlen( $packed ) ) {
				continue;
			}

			$full_bytes     = intdiv( (int) $prefix_length, 8 );
			$remaining_bits = (int) $prefix_length % 8;

			if ( substr( $packed, 0, $full_bytes ) !== substr( $packed_network, 0, $full_bytes ) ) {
				continue;
			}

			if ( 0 === $remaining_bits ) {
				return true;
			}

			$mask = 0xFF << ( 8 - $remaining_bits ) & 0xFF;

			if ( ( ord( $packed[ $full_bytes ] ) & $mask ) === ( ord( $packed_network[ $full_bytes ] ) & $mask ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check whether a string is a plain IP address or hostname.
	 *
	 * Accepts IPv4/IPv6 addresses (IPv6 optionally in brackets) and ASCII
	 * hostnames. Everything else is refused - most notably anything starting
	 * with a dash, which a command line tool would read as an option,
	 * anything containing whitespace, control or URL delimiter characters,
	 * and IP addresses in any other than the usual notation.
	 * Internationalized names have to be given in their punycode form.
	 *
	 * @param string $host The host to check.
	 * @return bool
	 */
	public static function is_valid_host( string $host ): bool {
		if ( '' === $host || strlen( $host ) > 253 ) {
			return false;
		}

		if ( str_starts_with( $host, '[' ) && str_ends_with( $host, ']' ) ) {
			return false !== filter_var( substr( $host, 1, -1 ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
		}

		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return true;
		}

		// \z instead of $: $ would also match before a trailing newline.
		if ( 1 !== preg_match( '/\A[A-Za-z0-9_][A-Za-z0-9_.-]*\z/', $host ) ) {
			return false;
		}

		/*
		 * A name whose last label is a number is not a name, but an IP
		 * address in an unusual notation: "2130706433", "127.1" and
		 * "0x7f.0.0.1" all mean 127.0.0.1 to one resolver or another - and
		 * not necessarily to all of them. No top-level domain is numeric,
		 * so nothing is lost by refusing them.
		 */
		$labels     = explode( '.', rtrim( $host, '.' ) );
		$last_label = (string) end( $labels );

		return 1 !== preg_match( '/\A(?:[0-9]+|0[xX][0-9A-Fa-f]*)\z/', $last_label );
	}
}
