# seaworthy-lab

The test harness of seaworthy's lab lanes, which test the contract between what the `seaworthy`
CLI packages and what the update helper installs, end to end, on real operating systems
([docs/testing.md](../../docs/testing.md)). Unpublished: lanes run its binary or link it as a
fixture; no product depends on it.

| Part | What it is |
|---|---|
| `seaworthy-lab serve` (feature `server`) | The lab server: a release tree from a directory, and a product's required-version endpoint |
| `seaworthy-lab ca` (feature `ca`) | A throwaway CA: a name-constrained root and one leaf for the lab's host names |
| `seaworthy-lab required-version` (feature `client`) | The required-version client the fixture's helper uses, from the command line |
| `seaworthy-lab foreign-manifest` | A signed release manifest re-signed by a throwaway key no build trusts |
| `conformance_server` (`crates/seaworthy-launcher/e2e/`) | `serve` alone, built beside the fixture in the lanes' builder image |
| `demo_helper` (`crates/seaworthy-launcher/e2e/`) | The fixture's update helper: seaworthy-updater's helper whose version source asks the lab |

The binary is built with `cargo build -p seaworthy-lab` (all features, the default). Every command
exits 0 on success, 1 on a failure (named on stderr) and 2 on a usage error.

## The lab server

```text
seaworthy-lab serve --root DIR (--token TOKEN | --token-file FILE) [--listen ADDR]...
                    [--ready FILE] [--hold FILE [--held FILE]] [--tls-cert PEM --tls-key PEM]
```

- `--root DIR`: the release tree. `GET` (or `HEAD`) `/<path>` answers the file `DIR/<path>`, the
  path percent-decoded as a static store decodes it (the helper sends a version token's `+` as
  `%2B`); `404` when there is none. A path with `..`, `.`, an empty segment, NUL, a control
  character, a backslash, a colon or a Windows device name is refused (`400`), so nothing outside
  `DIR` is ever served, on any platform. Paths under `/_lab/` are the lab's own and never served
  from `DIR`.
- `GET /_lab/required-version`: the product's **required-version endpoint**, answering the version
  token as one line of `text/plain`. `--token TOKEN` fixes it for the server's life;
  `--token-file FILE` reads `FILE` (whitespace trimmed) on every request, so a lane names another
  release by rewriting the file, without a restart. A token is 1-128 characters of
  `A-Z a-z 0-9 . _ + -` without `..`; a token file that isn't one answers `503`.
- `--listen ADDR` (repeatable; default `127.0.0.1:8470`): `127.0.0.1:443`, `[::1]:443`,
  `127.0.0.1:0` (an ephemeral port: read it from the ready file).
- `--ready FILE`: written once every listener is bound (whole or absent): `ready`, then one
  `listen <address>` line per address. Wait for it before the first request.
- `--hold FILE`: each required-version request first writes `--held FILE` (when given), then waits
  until `FILE` exists, at most two minutes; after that the connection is dropped, never answered
  late. Files are served meanwhile. This lets a lane change the machine while a helper run waits
  on its version source.
- `--tls-cert PEM --tls-key PEM` (both or neither): TLS, with the chain and key `seaworthy-lab ca`
  writes (`leaf.pem`, `leaf.key`). The configuration is built on seaworthy-crypto's TLS provider
  and protocol versions, the policy the update helper's client offers, with ALPN `http/1.1` and no
  client authentication.

One request per connection (`Connection: close`), at most 128 connections at once, a 30-second
deadline for the request head, and one log line per request on stderr:
`seaworthy-lab: <peer> <request line> <status> <bytes>`, control characters escaped. Lanes grep it
to see what the helper fetched. The server runs until it is killed.

## The throwaway CA

```text
seaworthy-lab ca --out DIR --name HOST [--name HOST]... [--days N]
```

Writes three new files into `DIR`: `ca.pem` (the root, for the machine's trust store),
`leaf.pem` and `leaf.key` (owner-only on unix: the server's chain and key). Names are plain DNS
names (lowercase, at least two labels, no wildcard), the first is the leaf's common name; `--days`
is 1-30 (default 2). The root:

- carries critical **name constraints** permitting exactly the given names (and their
  subdomains): a certificate it signed for any other host doesn't validate;
- has **no private key after the command ends**: the key lives in memory for the two signatures
  and is dropped, so nothing can issue another certificate under the root a machine trusts;
- names the run (`seaworthy lab CA <random>`), so a root a lane failed to remove is told apart.

Keys are ECDSA P-256 and every signature is seaworthy-crypto's; rcgen only encodes. Use names
under a reserved top-level domain (`.invalid`, which never resolves), pointed at the loopback by
the lane's hosts entries.

## The required-version client

```text
seaworthy-lab required-version --url URL [--timeout SECONDS]
```

Prints the token the endpoint answers, through exactly the TLS construction the fixture's helper
uses (seaworthy-crypto's client builder with the operating system's trust store, no proxy, no
redirects, bounded in time and size): a lane checks its CA, hosts entries and server with it before
it asks the helper to run. The URL is `https`, or `http` to a loopback address, without
credentials or a fragment.

## The foreign-key manifest

```text
seaworthy-lab foreign-manifest --manifest FILE --out FILE
```

Writes `FILE`'s release statement, byte for byte, signed by a fresh ML-DSA-87 key that is dropped
afterwards: a helper that refuses it refuses the key ("no trusted release key verified it"), never
a damaged statement.

## Driving the lab from PowerShell

Nothing in the interface is shell-specific. A Windows lane runs the same steps:

```powershell
$lab = "target\debug\seaworthy-lab.exe"
& $lab ca --out lab\tls --name packages.lab.invalid --name updates.lab.invalid
Import-Certificate -FilePath lab\tls\ca.pem -CertStoreLocation Cert:\LocalMachine\Root
Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "127.0.0.1 packages.lab.invalid updates.lab.invalid"
Set-Content lab\token -Value $candidateToken -NoNewline
$server = Start-Process $lab -PassThru -NoNewWindow -RedirectStandardError lab\server.log -ArgumentList @(
    'serve', '--root', 'lab\www', '--token-file', 'lab\token', '--listen', '127.0.0.1:443',
    '--ready', 'lab\ready', '--tls-cert', 'lab\tls\leaf.pem', '--tls-key', 'lab\tls\leaf.key')
while (-not (Test-Path lab\ready)) { Start-Sleep -Milliseconds 200 }
& $lab required-version --url https://updates.lab.invalid/_lab/required-version
# ... lay out lab\www\repo\releases\<package>\<channel>\<token>\<target>\<package>.msi(.manifest),
# start the helper's service, wait for its log ...
Stop-Process $server
```

The release tree's layout is the update helper's URL template: the fixture's helper is built with
`SEAWORTHY_LAB_PACKAGE_URL` and `SEAWORTHY_LAB_VERSION_URL` naming the lab
(`crates/seaworthy-launcher/e2e/demo_helper/build.rs`). Remove the root from the store and the
hosts entry when the lane ends, on every exit path.
