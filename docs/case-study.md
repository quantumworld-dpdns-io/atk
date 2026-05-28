# CVE-2026-42945 — Case Study

## Discovery: Autonomous Security Analysis

The vulnerability was discovered not by a human researcher, but by the
depthfirst security analysis platform. After a single click to onboard
the NGINX source repository, the system autonomously:

1. Built a code property graph of the ~200K line C codebase
2. Traced data flows through the script engine's two-pass architecture
3. Identified the state mismatch between `is_args` in main vs sub-engine
4. Generated a proof of concept demonstrating heap overflow
5. Produced a full vulnerability report with root cause analysis

The system found 5 issues in 6 hours. Four were confirmed by NGINX.

## Key Takeaways

### For Security Teams

1. **Legacy code is dangerous** — The bug lived for 18 years (2008–2026)
   across ~50 major releases. "Stable" does not mean "secure."

2. **Autonomous discovery changes the game** — depthfirst found this
   without human effort. Attackers will adopt similar tools.

3. **Config matters** — The bug requires a specific config pattern.
   Default nginx installs are not vulnerable, but common API gateway
   patterns trigger it.

4. **ASLR is not a panacea** — It prevents trivial RCE but not DoS.
   And ASLR bypass techniques exist.

### For NGINX Users

1. **Upgrade aggressively** — this was hidden for 18 years; other bugs
   may be hidden too.

2. **Audit rewrite configs** — if you use `rewrite` with `?` followed by
   `set`/`if`/`rewrite`, you're vulnerable.

3. **Use named captures** — they're not affected by this bug and are
   generally safer.

4. **Monitor for crashes** — worker SIGSEGV is a clear indicator.

## Lessons Learned

1. The two-pass engine design is elegant but fragile — any state
   divergence between passes causes memory corruption.

2. Flag management is critical — `is_args` should have been reset
   in `regex_end_code` from the start.

3. The fix is one line but finding it took autonomous analysis across
   the entire codebase.
