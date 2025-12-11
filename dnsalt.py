#!/usr/bin/env python3
"""
Generates various domain name permutations attacks for security testing. You'll see
the various attack types when you run it, these are also somewhat described in the code comments
"""


from typing import List, Dict
import argparse
import socket
import concurrent.futures
from datetime import datetime

# --------------------------------------------------------------------------------------------------
# dnsalt
# --------------------------------------------------------------------------------------------------
# Author: Simon Lundmark
# --------------------------------------------------------------------------------------------------
# Changelog:
# 2025-12-10: Somewhat finished and tested. Seems to work just fine now. //Simon
# --------------------------------------------------------------------------------------------------
# Install notes:
# All dependencies are in the Python 3 standard library, so you should be fine.
# --------------------------------------------------------------------------------------------------
# Current version:
VERSION = "v. 0.1"
# --------------------------------------------------------------------------------------------------
# Usage (use --help for detailed help):
# Example 1: Run with all default values and tample data:
# ./dnsalt.py example.com
# ./dnsalt.py example.com --help
# --------------------------------------------------------------------------------------------------


class dnsalt:
    """Generate domain name permutations, meaning adding different versions of that name by changing
    letters, adding symbols, or rearranging parts."""

    def __init__(self, domain: str):
        """
        Initialize with a domain name.

        Args: Full domain name (e.g., 'example.com').
        """
        self.original_domain = domain
        if '.' in domain:
            self.name, self.tld = domain.rsplit('.', 1)
        else:
            self.name = domain
            self.tld = 'com'

    # Declare character mappings to be used used.
    HOMOGLYPHS = {
        'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ', 'ǎ', 'ă', 'ȧ', 'ӓ'],
        'b': ['d', 'ʙ', 'Ь', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
        'c': ['ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç', 'č', 'ĉ'],
        'd': ['b', 'ԁ', 'ժ', 'ɗ', 'ď', 'đ', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ'],
        'e': ['é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'ẹ', 'ę', 'ȩ', 'ҽ', 'ӗ', 'е'],
        'f': ['ϝ', 'ƒ', 'ḟ'],
        'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ', 'ց', 'ǵ', 'ģ'],
        'h': ['һ', 'Һ', 'ḣ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ħ'],
        'i': ['1', 'l', 'í', 'ì', 'ï', 'î', 'ı', 'ɩ', 'ι', 'ꙇ', 'ǐ', 'ĭ', 'ɪ'],
        'j': ['ј', 'ʝ', 'ϳ', 'ɉ', 'ĵ'],
        'k': ['κ', 'ʞ', 'ќ', 'ķ', 'ҝ', 'ḱ', 'ḳ', 'ḵ'],
        'l': ['1', 'i', 'ʟ', 'Ɩ', 'ι', 'ӏ', 'ĺ', 'ļ', 'ľ', 'ḷ', 'ḹ', 'ḻ', 'ḽ'],
        'm': ['n', 'ṁ', 'ṃ', 'ᴍ', 'м', 'ɱ'],
        'n': ['m', 'r', 'ń', 'ṅ', 'ņ', 'ṇ', 'ṉ', 'ñ', 'ŋ', 'ɲ', 'ƞ', 'ӈ', 'ȵ'],
        'o': ['0', 'Ο', 'ο', 'О', 'о', 'Օ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ӧ'],
        'p': ['ρ', 'р', 'ƿ', 'Ϸ', 'ṗ', 'ṕ'],
        'q': ['g', 'զ', 'ԛ', 'գ', 'ʠ'],
        'r': ['ʀ', 'Ʀ', 'ɼ', 'ɽ', 'ŕ', 'ŗ', 'ř', 'ṙ', 'ṛ', 'ṝ', 'ṟ'],
        's': ['Ѕ', 'ʂ', 'ś', 'ṣ', 'ṡ', 'ş', 'š', 'ș'],
        't': ['τ', 'т', 'ţ', 'ť', 'ṫ', 'ṭ', 'ț', 'ṱ', 'ṯ'],
        'u': ['υ', 'ս', 'ʋ', 'ū', 'ú', 'ù', 'ü', 'û', 'ũ', 'ų', 'ụ', 'ủ', 'ư', 'ǔ', 'ŭ'],
        'v': ['ν', 'ѵ', 'ṿ', 'ʋ', 'ᶌ', 'ṽ', 'ⱱ'],
        'w': ['ʍ', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ', 'ŵ', 'ⱳ'],
        'x': ['х', 'ҳ', 'ẋ', 'ẍ'],
        'y': ['ʏ', 'у', 'ý', 'ÿ', 'ŷ', 'ẏ', 'ỳ', 'ỵ', 'ỷ', 'ỹ'],
        'z': ['ʐ', 'ż', 'ź', 'ʐ', 'ż', 'ź', 'ž', 'ẓ', 'ẕ', 'ⱬ']
    }

    KEYBOARD_ADJACENCY = {
        'q': ['w', 'a'],
        'w': ['q', 'e', 's'],
        'e': ['w', 'r', 'd'],
        'r': ['e', 't', 'f'],
        't': ['r', 'y', 'g'],
        'y': ['t', 'u', 'h'],
        'u': ['y', 'i', 'j'],
        'i': ['u', 'o', 'k'],
        'o': ['i', 'p', 'l'],
        'p': ['o', 'l'],
        'a': ['q', 's', 'z'],
        's': ['w', 'a', 'd', 'x'],
        'd': ['e', 's', 'f', 'c'],
        'f': ['r', 'd', 'g', 'v'],
        'g': ['t', 'f', 'h', 'b'],
        'h': ['y', 'g', 'j', 'n'],
        'j': ['u', 'h', 'k', 'm'],
        'k': ['i', 'j', 'l'],
        'l': ['o', 'k', 'p'],
        'z': ['a', 'x'],
        'x': ['z', 's', 'c'],
        'c': ['x', 'd', 'v'],
        'v': ['c', 'f', 'b'],
        'b': ['v', 'g', 'n'],
        'n': ['b', 'h', 'm'],
        'm': ['n', 'j']
    }

    VOWELS = ['a', 'e', 'i', 'o', 'u']

    # I just looked up the common most TLDs here.
    COMMON_TLDS = [
        'com', 'net', 'org', 'co', 'io', 'ai', 'biz', 'info', 'edu', 'gov',
        'uk', 'de', 'fr', 'cn', 'ru', 'br', 'in', 'au', 'ca', 'jp', 'xyz',
        'shop', 'pro'
    ]

    # You could just go completley nuts here, just added a few.
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'webmail', 'ftp', 'admin', 'portal', 'secure',
        'login', 'signin', 'account', 'shop', 'store', 'support',
        'help', 'blog', 'news', 'api', 'dev', 'staging', 'test'
    ]

    def homograph_attack(self) -> List[str]:
        """
        Generate homograph attack permutations using visually similar characters.
        Includes both single character and duplicate character replacements.

        Returns: List of domain permutations
        """
        results = []

        # Single character homograph substitutions.
        for i, char in enumerate(self.name):
            if char.lower() in self.HOMOGLYPHS:
                for homoglyph in self.HOMOGLYPHS[char.lower()]:
                    new_name = self.name[:i] + homoglyph + self.name[i+1:]
                    results.append(f"{new_name}.{self.tld}")

        # Duplicate character homograph substitutions.
        for i in range(len(self.name) - 1):
            if self.name[i] == self.name[i+1] and self.name[i].lower() in self.HOMOGLYPHS:
                for homoglyph in self.HOMOGLYPHS[self.name[i].lower()]:
                    # Replace both duplicate characters.
                    new_name = self.name[:i] + homoglyph + homoglyph + self.name[i+2:]
                    results.append(f"{new_name}.{self.tld}")

        return results

    def bitsquat_attack(self) -> List[str]:
        """
        Generate bitsquat attack permutations by flipping single bits in ASCII characters.

        Returns: List of domain permutations
        """
        results = []

        for i, char in enumerate(self.name):
            ascii_val = ord(char)

            # Flip each bit (0-7) in the ASCII value.
            for bit in range(8):
                flipped_val = ascii_val ^ (1 << bit)

                # Only include if it's a valid printable ASCII character.
                if 33 <= flipped_val <= 126:
                    flipped_char = chr(flipped_val)

                    # Only include alphanumeric and hyphen.
                    if flipped_char.isalnum() or flipped_char == '-':
                        new_name = self.name[:i] + flipped_char + self.name[i+1:]
                        results.append(f"{new_name}.{self.tld}")

        return results

    def hyphenation_attack(self) -> List[str]:
        """
        Generate hyphenation attack permutations by adding hyphens between characters.

        Returns: List of domain permutations
        """
        results = []

        # Add hyphen between each pair of characters.
        for i in range(1, len(self.name)):
            new_name = self.name[:i] + '-' + self.name[i:]
            results.append(f"{new_name}.{self.tld}")

        # Add hyphen at common word boundaries (heuristic approach),
        # look for consonant-vowel or vowel-consonant boundaries.
        for i in range(1, len(self.name)):
            prev_is_vowel = self.name[i-1].lower() in self.VOWELS
            curr_is_vowel = self.name[i].lower() in self.VOWELS

            if prev_is_vowel != curr_is_vowel:
                new_name = self.name[:i] + '-' + self.name[i:]
                if f"{new_name}.{self.tld}" not in results:
                    results.append(f"{new_name}.{self.tld}")

        return results

    def omission_attack(self) -> List[str]:
        """
        Generate omission attack permutations by removing single characters.

        Returns: List of domain permutations.
        """
        results = []

        for i in range(len(self.name)):
            new_name = self.name[:i] + self.name[i+1:]
            if new_name:  # Don't add empty names
                results.append(f"{new_name}.{self.tld}")

        return results

    def repetition_attack(self) -> List[str]:
        """
        Generate repetition attack permutations by repeating characters.

        Returns: List of domain permutations.
        """
        results = []

        # Repeat each character once.
        for i in range(len(self.name)):
            new_name = self.name[:i+1] + self.name[i] + self.name[i+1:]
            results.append(f"{new_name}.{self.tld}")

        # Also repeat already-doubled characters.
        for i in range(len(self.name) - 1):
            if self.name[i] == self.name[i+1]:
                new_name = self.name[:i+2] + self.name[i] + self.name[i+2:]
                results.append(f"{new_name}.{self.tld}")

        return results

    def replacement_attack(self) -> List[str]:
        """
        Generate replacement attack permutations by replacing characters with
        adjacent keyboard keys.

        Returns: List of domain permutations
        """
        results = []

        for i, char in enumerate(self.name):
            if char.lower() in self.KEYBOARD_ADJACENCY:
                for replacement in self.KEYBOARD_ADJACENCY[char.lower()]:
                    # Preserve original case
                    if char.isupper():
                        replacement = replacement.upper()

                    new_name = self.name[:i] + replacement + self.name[i+1:]
                    results.append(f"{new_name}.{self.tld}")

        return results

    def subdomain_attack(self) -> List[str]:
        """
        Generate subdomain attack permutations by adding common subdomains.

        Returns: List of domain permutations.
        """
        results = []

        for subdomain in self.COMMON_SUBDOMAINS:
            # Add subdomain prefix
            results.append(f"{subdomain}.{self.name}.{self.tld}")
            results.append(f"{subdomain}-{self.name}.{self.tld}")
            results.append(f"{self.name}-{subdomain}.{self.tld}")
            results.append(f"{subdomain}{self.name}.{self.tld}")
            results.append(f"{self.name}{subdomain}.{self.tld}")

        return results

    def transposition_attack(self) -> List[str]:
        """
        Generate transposition attack permutations by swapping adjacent characters.

        Returns: List of domain permutations.
        """
        results = []

        for i in range(len(self.name) - 1):
            new_name = (self.name[:i] + 
                       self.name[i+1] + 
                       self.name[i] + 
                       self.name[i+2:])
            results.append(f"{new_name}.{self.tld}")

        return results

    def vowel_swap_attack(self) -> List[str]:
        """
        Generate vowel swap attack permutations by replacing vowels with other vowels.

        Returns: List of domain permutations.
        """
        results = []

        for i, char in enumerate(self.name):
            if char.lower() in self.VOWELS:
                for vowel in self.VOWELS:
                    if vowel != char.lower():
                        # Preserve original case
                        if char.isupper():
                            vowel = vowel.upper()

                        new_name = self.name[:i] + vowel + self.name[i+1:]
                        results.append(f"{new_name}.{self.tld}")

        return results

    def addition_attack(self) -> List[str]:
        """
        Generate addition attack permutations by adding single characters.

        Returns: List of domain permutations
        """
        results = []
        characters = 'abcdefghijklmnopqrstuvwxyz0123456789'

        # Add character at each position.
        for i in range(len(self.name) + 1):
            for char in characters:
                new_name = self.name[:i] + char + self.name[i:]
                results.append(f"{new_name}.{self.tld}")

        return results

    def doppelganger_attack(self) -> List[str]:
        """
        Generate doppelganger attack permutations by using different TLDs.

        Returns: List of domain permutations
        """
        results = []

        for tld in self.COMMON_TLDS:
            if tld != self.tld:
                results.append(f"{self.name}.{tld}")

        return results

    def generate_all(self) -> dict:
        """
        Generate all permutation types.

        Returns: Dictionary with attack type as key and list of permutations as value
        """
        return {
            'original': [self.original_domain],
            'homograph': self.homograph_attack(),
            'bitsquat': self.bitsquat_attack(),
            'hyphenation': self.hyphenation_attack(),
            'omission': self.omission_attack(),
            'repetition': self.repetition_attack(),
            'replacement': self.replacement_attack(),
            'subdomain': self.subdomain_attack(),
            'transposition': self.transposition_attack(),
            'vowel_swap': self.vowel_swap_attack(),
            'addition': self.addition_attack(),
            'doppelganger': self.doppelganger_attack()
        }

    @staticmethod
    def check_domain_resolution(domain: str, timeout: float = 2.0) -> Dict[str, any]:
        """
        Check if a domain resolves to an IP address.

        Args: Domain name to check.
              DNS query timeout in seconds.

        Returns: Dictionary with resolution results
        """
        result = {
            'domain': domain,
            'resolves': False,
            'ip_addresses': [],
            'error': None
        }

        try:
            # Set socket timeout
            socket.setdefaulttimeout(timeout)

            # Try to resolve the domain
            ip_addresses = socket.gethostbyname_ex(domain)[2]

            if ip_addresses:
                result['resolves'] = True
                result['ip_addresses'] = ip_addresses

        except socket.gaierror as e:
            # Domain doesn't resolve or DNS error
            result['error'] = str(e)
        except socket.timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = f'Error: {str(e)}'

        return result


def check_domains_bulk(domains: List[str], max_workers: int = 20, timeout: float = 2.0, verbose: bool = True) -> List[Dict]:
    """
    Check multiple domains for DNS resolution in parallel.

    Args: List of domain names to check.
          Maximum number of concurrent threads.
          DNS query timeout per domain in seconds.
          Show progress information.

    Returns: List of dictionaries with resolution results
    """
    results = []
    total = len(domains)

    if verbose:
        print(f"\n{'='*60}")
        print(f"DNS RESOLUTION CHECK")
        print(f"{'='*60}")
        print(f"Checking {total} domains (timeout: {timeout}s, workers: {max_workers})")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_domain = {
            executor.submit(DomainPermutator.check_domain_resolution, domain, timeout): domain 
            for domain in domains
        }

        # Process completed tasks
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            results.append(result)
            completed += 1

            if verbose and completed % 50 == 0:
                print(f"Progress: {completed}/{total} domains checked ({completed/total*100:.1f}%)")

            # Show resolved domains immediately if verbose
            if verbose and result['resolves']:
                ips = ', '.join(result['ip_addresses'])
                print(f"✓ ACTIVE: {result['domain']} → {ips}")

    if verbose:
        resolved_count = sum(1 for r in results if r['resolves'])
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        print(f"Total checked: {total}")
        print(f"Active domains: {resolved_count}")
        print(f"Inactive domains: {total - resolved_count}")
        print(f"Success rate: {resolved_count/total*100:.1f}%")
        print(f"{'='*60}\n")

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Generate domain name permutations for security testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  homograph     - Visually similar characters (e.g., o -> 0, l -> 1)
  bitsquat      - Single bit flips in ASCII characters
  hyphenation   - Adding hyphens between characters
  omission      - Removing characters
  repetition    - Repeating characters
  replacement   - Adjacent keyboard key replacements
  subdomain     - Adding common subdomains
  transposition - Swapping adjacent characters
  vowel_swap    - Replacing vowels with other vowels
  addition      - Adding characters
  doppelganger  - Using different TLDs

Examples:
  python domain_permutations.py example.com
  python domain_permutations.py example.com --attack homograph
  python domain_permutations.py example.com --attack transposition --limit 20
  python domain_permutations.py example.com --output permutations.txt

  # Check DNS resolution for generated domains
  python domain_permutations.py example.com --resolve
  python domain_permutations.py example.com --resolve --only-active
  python domain_permutations.py example.com --attack omission --resolve --workers 50
  python domain_permutations.py example.com --resolve --timeout 3.0 --output active.txt
        """
    )

    parser.add_argument('domain', help='Domain name to generate permutations for')
    parser.add_argument(
        '--attack', '-a',
        choices=['homograph', 'bitsquat', 'hyphenation', 'omission', 
                'repetition', 'replacement', 'subdomain', 'transposition',
                'vowel_swap', 'addition', 'doppelganger', 'all'],
        default='all',
        help='Type of attack to generate (default: all).'
    )
    parser.add_argument(
        '--limit', '-l',
        type=int,
        help='Limit number of results per attack type.'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: print to stdout).'
    )
    parser.add_argument(
        '--no-duplicates',
        action='store_true',
        help='Remove duplicate domains across attack types.'
    )
    parser.add_argument(
        '--resolve',
        action='store_true',
        help='Check DNS resolution for generated domains.'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=2.0,
        help='DNS resolution timeout in seconds (default: 2.0).'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=20,
        help='Number of concurrent DNS resolution workers (default: 20).'
    )
    parser.add_argument(
        '--only-active',
        action='store_true',
        help='Show only domains that resolve (requires --resolve).'
    )

    args = parser.parse_args()

    # Validate arguments.
    if args.only_active and not args.resolve:
        parser.error("--only-active requires --resolve")

    # Create permutator.
    permutator = DomainPermutator(args.domain)

    # Generate permutations.
    if args.attack == 'all':
        results = permutator.generate_all()
    else:
        attack_method = getattr(permutator, f"{args.attack}_attack")
        results = {args.attack: attack_method()}

    # Collect all domains.
    all_domains_list = []
    for attack_type, domains in results.items():
        if args.limit:
            domains = domains[:args.limit]
        all_domains_list.extend(domains)

    # Remove duplicates if requested.
    if args.no_duplicates:
        all_domains_list = list(dict.fromkeys(all_domains_list))  # Preserve order.

    # Check DNS resolution if requested.
    resolution_results = {}
    if args.resolve:
        dns_results = check_domains_bulk(
            all_domains_list,
            max_workers=args.workers,
            timeout=args.timeout,
            verbose=True
        )

        # Create lookup dictionary.
        resolution_results = {r['domain']: r for r in dns_results}

    # Prepare output.
    output_lines = []

    for attack_type, domains in results.items():
        if args.limit:
            domains = domains[:args.limit]

        # Apply duplicate removal if needed.
        if args.no_duplicates:
            seen = set()
            unique_domains = []
            for d in domains:
                if d not in seen:
                    seen.add(d)
                    unique_domains.append(d)
            domains = unique_domains

        # Filter for active domains if requested.
        if args.only_active and args.resolve:
            domains = [d for d in domains if resolution_results.get(d, {}).get('resolves', False)]

        if not domains:
            continue

        output_lines.append(f"\n{'='*60}")
        output_lines.append(f"{attack_type.upper()} ATTACK")
        output_lines.append(f"{'='*60}")
        output_lines.append(f"Generated {len(domains)} permutations\n")

        for domain in domains:
            if args.resolve and domain in resolution_results:
                res = resolution_results[domain]
                if res['resolves']:
                    ips = ', '.join(res['ip_addresses'])
                    output_lines.append(f"✓ {domain} → {ips}")
                elif not args.only_active:
                    output_lines.append(f"✗ {domain}")
            else:
                output_lines.append(domain)

    # Add summary.
    if args.no_duplicates or args.resolve:
        output_lines.append(f"\n{'='*60}")
        output_lines.append("SUMMARY")
        output_lines.append(f"{'='*60}")

        if args.no_duplicates:
            output_lines.append(f"Total unique domains: {len(all_domains_list)}")

        if args.resolve:
            active_count = sum(1 for r in resolution_results.values() if r['resolves'])
            output_lines.append(f"Active domains: {active_count}/{len(resolution_results)}")

            if active_count > 0:
                output_lines.append(f"\n⚠️  WARNING: {active_count} potentially suspicious domains are active!")

        output_lines.append(f"{'='*60}")

    # Output results.
    output_text = '\n'.join(output_lines)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output_text)
        print(f"\nResults written to {args.output}")
        if args.resolve:
            active_count = sum(1 for r in resolution_results.values() if r['resolves'])
            print(f"Found {active_count} active domains out of {len(resolution_results)} checked")
    else:
        print(output_text)


def super_cool_banner():
    """This program will probably not even work without this."""
    print("\n" * 5)
    print("""
       _            _             _            _                   _           _       
      /\ \         /\ \     _    / /\         / /\                _\ \        /\ \     
     /  \ \____   /  \ \   /\_\ / /  \       / /  \              /\__ \       \_\ \    
    / /\ \_____\ / /\ \ \_/ / // / /\ \__   / / /\ \            / /_ \_\      /\__ \   
   / / /\/___  // / /\ \___/ // / /\ \___\ / / /\ \ \          / / /\/_/     / /_ \ \  
  / / /   / / // / /  \/____/ \ \ \ \/___// / /  \ \ \        / / /         / / /\ \ \ 
 / / /   / / // / /    / / /   \ \ \     / / /___/ /\ \      / / /         / / /  \/_/ 
/ / /   / / // / /    / / /_    \ \ \   / / /_____/ /\ \    / / / ____    / / /        
\ \ \__/ / // / /    / / //_/\__/ / /  / /_________/\ \ \  / /_/_/ ___/\ / / /         
 \ \___\/ // / /    / / / \ \/___/ /  / / /_       __\ \_\/_______/\__\//_/ /          
  \/_____/ \/_/     \/_/   \_____\/   \_\___\     /____/_/\_______\/    \_\/           
                                                                                       
                                Put some salt on your records.
    """)


if __name__ == '__main__':
    super_cool_banner()
    main()
