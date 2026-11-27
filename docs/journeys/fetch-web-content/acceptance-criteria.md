# Fetch Web Content: Acceptance Criteria

An **Agent** or **CLI User** submits a **Fetch Request** for a public HTTP(S) **Target URL** in a web **Format**
(`html`, `markdown`, `readable`, `text`, or `json`) and receives a **Windowed Excerpt** or a typed domain error.
Built slice by slice, starting in the harness and wiring into the real HTTP transport and CLI ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Agent** and **CLI User** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@FW-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Submit Fetch Request.** Actor submits a Fetch Request with a Target URL, Format, optional custom headers, and optional Window bounds.
2. **Validate Target URL & Resolve Host.** System enforces SSRF rules on the Target URL and resolves and pins public DNS records on direct connections.
3. **Retrieve Raw Response.** System performs a single-attempt HTTP(S) `GET`, following validated redirects, decompressing supported encodings, enforcing byte and timeout limits, and checking status and Content-Type.
4. **Render Format.** System transforms the Raw Response into Rendered Output for the requested Format.
5. **Slice Windowed Excerpt.** System slices Rendered Output into a Windowed Excerpt and delivers it (or a typed error) to the actor.

## 1. Submit Fetch Request

```gherkin
@FW-1 @D4 @D14
Scenario: Malformed Target URL is rejected before any network call
  Given an Agent or CLI User submits a Fetch Request with Target URL "not-a-url" and Format "html"
  When they fetch
  Then the Fetch Request is refused with a typed validation error (D14)

@FW-1 @D4 @D14
Scenario: Invalid Window bounds or unsupported Format are rejected before any network call
  Given an Agent or CLI User submits a Fetch Request with a negative startIndex or negative maxLength or unknown Format
  When they fetch
  Then the Fetch Request is refused with a typed validation error (D14)

@FW-2 @D18
Scenario: Default User-Agent and Accept-Encoding are applied only when caller does not supply them
  Given a public Remote Origin Server records incoming request headers for "https://example.com/"
  When the actor runs fetch for "https://example.com/" in Format "html" with custom header "user-agent: CustomBot/1.0"
  Then the origin receives "CustomBot/1.0" without a duplicate default User-Agent header (D18)
  And the origin receives the default Accept-Encoding header (D18)

@FW-2 @D14 @D18
Scenario: Custom headers containing CR or LF control characters are rejected
  Given an Agent or CLI User submits a Fetch Request with a custom header value containing a newline
  When they fetch
  Then the Fetch Request is refused with a typed validation error before connecting (D14, D18)
```

## 2. Validate Target URL & Resolve Host

```gherkin
@FW-3 @D8 @I1
Scenario: Disallowed URL schemes are blocked before connecting
  Given an Agent or CLI User submits a Fetch Request for "file:///etc/passwd" or "ftp://example.com/data"
  When they fetch
  Then the Fetch Request is refused as a blocked Target URL (D8, I1)

@FW-3 @D8 @I1
Scenario: Localhost and IANA-reserved IPv4/IPv6 literals are blocked before connecting
  Given an Agent or CLI User submits a Fetch Request targeting "localhost", "api.localhost", "127.0.0.1", "169.254.169.254", "[::1]", "[::ffff:127.0.0.1]", or a multicast IP
  When they fetch
  Then the Fetch Request is refused as a blocked Target URL (D8, I1)

@FW-4 @D8 @I2
Scenario: Direct connection resolves DNS, pins validated public IPs, and blocks private or failed lookups
  Given the DNS Resolver maps "rebind.example.com" to a public IP and a reserved IP "10.0.0.5"
  When the actor runs fetch for "https://rebind.example.com/" in Format "html"
  Then the Fetch Request is refused before connecting to any socket (D8, I2)

@FW-4 @D8 @I2
Scenario: Direct connection fails closed when DNS resolution fails or returns no addresses
  Given the DNS Resolver fails or returns an empty address list for "missing.example.com"
  When the actor runs fetch for "https://missing.example.com/" in Format "html"
  Then the Fetch Request is refused as a blocked Target URL (D8, I2)
```

## 3. Retrieve Raw Response

```gherkin
@FW-5 @D4 @D14 @D18
Scenario: Single-attempt fetch returns a 2xx Raw Response
  Given the Remote Origin Server serves HTTP 200 HTML at "https://example.com/"
  When the actor runs fetch for "https://example.com/" in Format "html"
  Then the origin receives exactly one GET request and the actor receives the Windowed Excerpt (D18)

@FW-5 @D14 @D18
Scenario: Non-2xx HTTP status or network error fails explicitly without retrying
  Given the Remote Origin Server responds with HTTP 500 at "https://example.com/fail"
  When the actor runs fetch for "https://example.com/fail" in Format "html"
  Then the origin receives exactly one request and the actor receives a typed HTTP error (D14, D18)

@FW-6 @D8 @D9 @I1 @I2 @I4
Scenario: Public redirects are followed and sensitive headers are stripped cross-origin
  Given "https://origin-a.example.com/start" redirects (302) to "https://origin-b.example.com/final"
  And the actor passes "Authorization", "Cookie", and "X-Custom" headers
  When they fetch "https://origin-a.example.com/start" in Format "html"
  Then "origin-b.example.com" receives "X-Custom" but not "Authorization" or "Cookie" (D9, I4)
  And the actor receives the Rendered Output from "https://origin-b.example.com/final"

@FW-6 @D8 @I1 @I2
Scenario: Redirect to a private host or disallowed scheme is blocked before connecting
  Given "https://example.com/start" redirects (302) to "http://127.0.0.1/admin"
  When the actor runs fetch for "https://example.com/start" in Format "html"
  Then the Fetch Request is refused as a blocked Target URL before any request reaches "127.0.0.1" (D8, I1)

@FW-6 @D9 @D14 @D17
Scenario: Redirect loop exceeding limit or redirect without Location fails explicitly
  Given "https://example.com/loop" redirects past the redirect limit (D9) or returns 302 with no Location header (D17)
  When the actor runs fetch for "https://example.com/loop" in Format "html"
  Then the actor receives a typed redirect or HTTP error (D9, D14, D17)

@FW-7 @D9 @D17 @I5
Scenario: Supported compressed responses are decompressed and raw and decoded byte caps are enforced
  Given the Remote Origin Server serves a gzip-encoded body within MAX_RESPONSE_BYTES
  When the actor runs fetch in Format "html"
  Then the actor receives the decompressed Rendered Output (D17)

@FW-7 @D9 @D14 @I5
Scenario: Oversized Content-Length, raw stream, or decompressed stream is rejected
  Given the Remote Origin Server returns a response exceeding MAX_RESPONSE_BYTES in declared Content-Length, raw wire bytes, or decompressed bytes
  When the actor runs fetch in Format "html"
  Then reading stops immediately and the actor receives a typed size-limit error (D9, D14, I5)

@FW-7 @D17
Scenario: Unknown Content-Encoding is passed through unchanged
  Given the Remote Origin Server returns Content-Encoding "custom-enc" with UTF-8 text within MAX_RESPONSE_BYTES
  When the actor runs fetch in Format "html"
  Then the actor receives the body text unchanged (D17)

@FW-8 @D9 @D14 @D18
Scenario: Slow origin exceeding timeout fails explicitly without retrying
  Given the Remote Origin Server does not respond within the timeout (D9)
  When the actor runs fetch in Format "html"
  Then the request is aborted and the actor receives a typed timeout error without retries (D9, D14, D18)

@FW-9 @D14 @D17
Scenario: Binary Content-Type responses are rejected with a typed error
  Given the Remote Origin Server returns Content-Type "image/png" or "application/pdf" or "application/octet-stream"
  When the actor runs fetch in Format "html"
  Then the Fetch Request is refused with a typed unsupported-content error (D14, D17)
```

## 4. Render Format

```gherkin
@FW-10 @D4 @D16
Scenario: Format html returns the unmodified response text
  Given the Remote Origin Server returns HTML "<h1>Hello</h1><script>x()</script>"
  When the actor runs fetch in Format "html"
  Then Rendered Output is the exact unmodified response text (D16)

@FW-11 @D4 @D14 @D16
Scenario: Format json returns compact re-serialized JSON and rejects invalid JSON
  Given the Remote Origin Server returns valid JSON "{ \"a\": 1, \"b\": [2, 3] }"
  When the actor runs fetch in Format "json"
  Then Rendered Output is compact JSON "{\"a\":1,\"b\":[2,3]}" (D16)

@FW-11 @D4 @D14 @D16
Scenario: Format json fails explicitly on invalid JSON
  Given the Remote Origin Server returns non-JSON text "<html>not json</html>"
  When the actor runs fetch in Format "json"
  Then the actor receives a typed parse error (D14, D16)

@FW-12 @D4 @D16
Scenario: Format text strips script and style elements and normalizes whitespace
  Given the Remote Origin Server returns HTML containing <script>, <style>, and multi-whitespace text
  When the actor runs fetch in Format "text"
  Then Rendered Output excludes script and style contents and collapses whitespace (D16)

@FW-12 @D4 @D16
Scenario: Format markdown strips script and style elements before converting to Markdown
  Given the Remote Origin Server returns HTML containing <script>, <style>, headings, and links
  When the actor runs fetch in Format "markdown"
  Then Rendered Output is Markdown excluding script and style contents (D16)

@FW-13 @D4 @D14 @D16
Scenario: Format readable extracts main article with title heading and strips boilerplate
  Given the Remote Origin Server returns an article HTML page with navigation boilerplate and a title
  When the actor runs fetch in Format "readable"
  Then Rendered Output begins with "# <article.title>" followed by the article body as Markdown without boilerplate (D16)

@FW-13 @D4 @D14 @D16
Scenario: Format readable fails explicitly when Readability cannot parse an article
  Given the Remote Origin Server returns content Readability cannot extract an article from
  When the actor runs fetch in Format "readable"
  Then the actor receives a typed parse error (D14, D16)
```

## 5. Slice Windowed Excerpt

```gherkin
@FW-14 @D4 @D9 @D14 @D15
Scenario: Windowed Excerpt applies default limit, custom window, unlimited mode, and out-of-range startIndex
  Given Rendered Output has 20 characters "0123456789abcdefghij"
  When the actor runs fetch with startIndex 5 and maxLength 6
  Then the Windowed Excerpt is "56789a" with no appended footer or metadata (D15)
  When the actor runs fetch with maxLength 0
  Then the Windowed Excerpt is the full Rendered Output (D9, D15)
  When the actor runs fetch with startIndex 20 and maxLength 10
  Then the Windowed Excerpt is empty "" (D14, D15)

@FW-15 @D1 @D6 @D12 @D14
Scenario: CLI User fetches web content via mcp-fetch subcommands and flags
  Given a public Remote Origin Server serves a page at "https://example.com/"
  When the CLI User runs `mcp-fetch <format> https://example.com/ --header "Accept: text/html" --start-index 0 --max-length 100`
  Then the Windowed Excerpt is written to stdout and the process exits with code 0 (D1, D6, D12)
  And when fetch fails with a typed error, the error message is written to stderr and the process exits with code 1 (D14)
```
