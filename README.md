# juice-shop-assessment
Application security assessment of OWASP Juice Shop using Semgrep (SAST) with manual validation of findings and remediation guidance.
## Findings (Semgrep SAST, server code)

| # | Finding | OWASP category | File | Severity | Validated? | Recommended fix |
|---|---------|----------------|------|----------|------------|-----------------|
| 1 | SQL injection in login query | A03 Injection | routes/login.ts | High | | Use parameterised queries |
| 2 | SQL injection in product search | A03 Injection | routes/search.ts | High | | Use parameterised queries |
| 3 | Path traversal via res.sendFile | A01 Broken Access Control | routes/fileServer.ts (and 3 similar files) | Medium | | Validate and canonicalise the path |
| 4 | Open redirect | A01 Broken Access Control | routes/redirect.ts | Medium | | Allow-list permitted URLs |
| 5 | User input passed to eval | A03 Injection | routes/userProfile.ts | High | | Remove eval, use safe parsing |
# OWASP Juice Shop: Application Security Assessment

Application security assessment of OWASP Juice Shop using Semgrep (SAST), with manual validation of findings and remediation guidance.

## Overview
I ran a static application security testing (SAST) scan against the OWASP Juice Shop server codebase using Semgrep's OWASP Top Ten ruleset, then manually validated the most significant findings against the live running application to confirm they were real, exploitable issues rather than false positives.

**Date:** October 2026
**Scope:** Local instance only (localhost:3000), server-side code (routes, lib, models)

## Tools used
- Semgrep (SAST) — static code analysis
- Docker — running Juice Shop and Semgrep locally
- Browser dev tools — manual validation

## Setup
docker run -d -p 3000:3000 bkimminich/juice-shop
git clone https://github.com/juice-shop/juice-shop
docker run --rm -v “juice-shop:/src” -v “evidence:/out” semgrep/semgrep semgrep scan --config p/owasp-top-ten --json --output /out/semgrep-results.json /src/routes /src/lib /src/models /src/server.ts

## Findings

| # | Finding | OWASP Category | Location | Severity | Validated | Fix |
|---|---------|----------------|----------|----------|-----------|-----|
| 1 | SQL injection in login (authentication bypass) | A03: Injection | routes/login.ts | High | **Confirmed** — logged in as admin using `' OR 1=1--` as the email | Use parameterised queries instead of string concatenation |
| 2 | SQL injection in product search | A03: Injection | routes/search.ts | High | **Confirmed** — UNION-based payload triggered a raw SQLITE_ERROR, also disclosing the Express version | Use parameterised queries; return generic error messages |
| 3 | Path traversal via file server | A01: Broken Access Control | routes/fileServer.ts, keyServer.ts, logfileServer.ts, quarantineServer.ts | Medium | Partially tested — file extension allow-list (.md/.pdf) blocked an unrelated file, but `../` traversal could not be tested from the browser alone, since browsers normalise `../` client-side before sending the request. Proper testing would need a proxy tool (e.g. Burp Suite) | Canonicalise and validate the resolved path stays inside the intended directory |
| 4 | Open redirect | A01: Broken Access Control | routes/redirect.ts | Medium | Not manually validated (code review only) | Use an allow-list of permitted redirect URLs |
| 5 | User input passed to eval() | A03: Injection | routes/userProfile.ts | High | Not manually validated (code review only) | Remove eval(); use safe parsing instead |

## Additional observations
- **Verbose error disclosure:** Unhandled errors return full stack traces revealing internal server file paths (e.g. `/juice-shop/build/routes/fileServer.js`), which could help an attacker map the application structure.
- **Version disclosure:** Error pages reveal the exact Express framework version (4.22.1) in the page title, useful for an attacker researching known vulnerabilities for that version.

## Remediation example
The login query concatenates user input directly into SQL:
```js
// Vulnerable
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' ...`)

// Fixed — parameterised query
models.sequelize.query(
  `SELECT * FROM Users WHERE email = :email AND password = :password`,
  { replacements: { email: req.body.email, password: hashedPassword } }
)
```

## What I learned
Running a scanner is only the first step, most of the value came from manually validating findings against the live application rather than trusting the tool's output blindly. I also learned that browser-based testing has real limitations (URL normalisation), which taught me why tools like Burp Suite exist as a proxy between the browser and the server.

## Disclaimer
This assessment was performed only against a local instance of OWASP Juice Shop, a deliberately vulnerable application designed for security training. No external or production systems were tested.
