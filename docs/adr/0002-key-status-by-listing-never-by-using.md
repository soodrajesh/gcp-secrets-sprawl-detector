# ADR 0002: ask whether a leaked key is live by listing keys, never by using it

**Decision**: for service-account keys, list the account's user-managed keys with the scanner's own read-only identity and compare key ids.
**Why**: authenticating with a found credential is itself an access to someone's account; and the runtime role can list keys but not get them.
**Consequence**: other credential types (GitHub, Stripe, AWS) are not validated; severity relies on type and exposure.
