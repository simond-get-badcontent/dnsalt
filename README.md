# Domain Name Permutation Generator

A Python script for generating domain name permutations stuff to detect typosquatting, cybersquatting, and phishing domains. Useful for security research, brand protection, and penetration testing.

## Features

This script generates 11 different types of domain permutations and can check if they resolve (are registered):

### Attack Types

1. **Homograph Attack** - Replaces characters with visually similar ones
   - Single character: `google.com` → `g00gle.com` (o→0)
   - Duplicate characters: `google.com` → `gοοgle.com` (oo→οο)

2. **Bitsquat Attack** - Flips single bits in ASCII characters
   - `google.com` → `foogle.com`, `gmogle.com`, `eoogle.com`

3. **Hyphenation Attack** - Adds hyphens between characters
   - `google.com` → `g-oogle.com`, `go-ogle.com`, `goo-gle.com`

4. **Omission Attack** - Removes characters
   - `google.com` → `gogle.com`, `goole.com`, `googl.com`

5. **Repetition Attack** - Repeats characters
   - `google.com` → `ggoogle.com`, `gooogle.com`, `gooogle.com`

6. **Replacement Attack** - Replaces with adjacent keyboard keys
   - `google.com` → `foogle.com`, `hoogle.com`, `goodle.com`

7. **Subdomain Attack** - Adds common subdomains
   - `google.com` → `www.google.com`, `mail-google.com`, `google-login.com`

8. **Transposition Attack** - Swaps adjacent characters
   - `google.com` → `ogogle.com`, `goolge.com`, `googel.com`

9. **Vowel Swap Attack** - Replaces vowels with other vowels
   - `google.com` → `guogle.com`, `gaogle.com`, `googli.com`

10. **Addition Attack** - Adds single characters
    - `google.com` → `agoogle.com`, `goaogle.com`, `google1.com`

11. **Doppelganger Attack** - Uses different TLDs
    - `google.com` → `google.net`, `google.org`, `google.io`

## Installation

No external dependencies required. Uses only Python standard library.

## DNS Resolution Checking

The script can check which generated domains actually resolve (are registered and active). This is nice for identifying **actual typosquatting threats** versus theoretical ones (saves to time).

### How It Works

- Uses multi-threaded DNS resolution for fast checking.
- Configurable timeout and worker threads.
- Shows IP addresses for active domains.
- Can filter to show only active domains.

### Ok fine, but why should I care?

- **Prioritize threats**: Focus on domains that are actually registered
- **Identify typosquatters**: Find malicious actors using similar domains
- **Brand protection**: Discover domains impersonating your brand
- **Save time**: No need to manually check thousands of domains

## Usage

### Basic Usage

Generate all permutation types for a domain:

```bash
python domain_permutations.py example.com
```

### Specific Attack Type

Generate only specific attack permutations:

```bash
python domain_permutations.py example.com --attack homograph
python domain_permutations.py example.com --attack transposition
python domain_permutations.py example.com -a bitsquat
```

### Limit Results

Limit the number of results per attack type:

```bash
python domain_permutations.py example.com --limit 50
python domain_permutations.py example.com -a addition -l 100
```

### Save to File

Save results to a file:

```bash
python domain_permutations.py example.com --output permutations.txt
python domain_permutations.py example.com -o results.txt
```

### Remove Duplicates

Remove duplicate domains across different attack types:

```bash
python domain_permutations.py example.com --no-duplicates
```

### Combined Options

```bash
python domain_permutations.py example.com \
  --attack homograph \
  --limit 100 \
  --output homograph_domains.txt \
  --no-duplicates
```

### DNS Resolution Checking

Check which generated domains actually resolve:

```bash
# Check all generated domains for DNS resolution:
python domain_permutations.py example.com --resolve

# Check with custom timeout and worker threads:
python domain_permutations.py example.com --resolve --timeout 3.0 --workers 50

# Show only active (registered) domains:
python domain_permutations.py example.com --resolve --only-active

# Combine with specific attack types:
python domain_permutations.py example.com --attack omission --resolve --only-active

# Save active domains to file:
python domain_permutations.py example.com --resolve --only-active --output active_threats.txt
```

## Command-Line Options

```
positional arguments:
  domain                Domain name to generate permutations for

optional arguments:
  -h, --help            Show help message and exit
  
  --attack {homograph,bitsquat,hyphenation,omission,repetition,replacement,subdomain,transposition,vowel_swap,addition,doppelganger,all}
  -a                    Type of attack to generate (default: all)
  
  --limit LIMIT
  -l LIMIT             Limit number of results per attack type
  
  --output OUTPUT
  -o OUTPUT            Output file path (default: print to stdout)
  
  --no-duplicates      Remove duplicate domains across attack types
  
  --resolve            Check DNS resolution for generated domains
  
  --timeout TIMEOUT    DNS resolution timeout in seconds (default: 2.0)
  
  --workers WORKERS    Number of concurrent DNS resolution workers (default: 20)
  
  --only-active        Show only domains that resolve (requires --resolve)
```

## API Usage

You can also use the `DomainPermutator` class in your own Python scripts:

```python
from domain_permutations import DomainPermutator, check_domains_bulk

# Create permutator
permutator = DomainPermutator("example.com")

# Generate specific attack type
homograph_domains = permutator.homograph_attack()
transposition_domains = permutator.transposition_attack()

# Generate all attacks
all_permutations = permutator.generate_all()

# Process results
for attack_type, domains in all_permutations.items():
    print(f"{attack_type}: {len(domains)} permutations")
    for domain in domains[:5]:  # Show first 5
        print(f"  {domain}")

# Check DNS resolution for a single domain
result = DomainPermutator.check_domain_resolution("g00gle.com", timeout=2.0)
if result['resolves']:
    print(f"{result['domain']} is ACTIVE: {result['ip_addresses']}")
else:
    print(f"{result['domain']} is inactive")

# Check DNS resolution for multiple domains (parallel)
domains_to_check = homograph_domains[:100]
resolution_results = check_domains_bulk(
    domains_to_check,
    max_workers=20,
    timeout=2.0,
    verbose=True
)

# Filter for active domains
active_domains = [r for r in resolution_results if r['resolves']]
print(f"\nFound {len(active_domains)} active domains:")
for result in active_domains:
    ips = ', '.join(result['ip_addresses'])
    print(f"  ⚠️  {result['domain']} → {ips}")
```

## Warning

This tool is intended for **legitimate security research and defensive purposes only**. Don't be an a**hole.
