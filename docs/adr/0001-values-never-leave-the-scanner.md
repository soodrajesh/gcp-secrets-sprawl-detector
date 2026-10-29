# ADR 0001: values never leave the scanner

**Decision**: the Finding model has no field for a secret value; the scanner returns a masked preview and a salted HMAC fingerprint, and nothing else, to the API, UI, CLI and models.
**Why**: a secrets scanner that stores or prints what it finds becomes the best target in the environment; and sending values to a model vendor would be a leak of its own.
**Consequence**: the model can only explain from metadata, and previews show 4 + 2 characters; tests assert no value appears in any output.
