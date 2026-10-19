# Ollama request deadlines

Harbinger bounds its Ollama HTTP requests with `AbortController` deadlines.
Model discovery uses 30 seconds and keeps the deadline active until the response
body has been read. Discovery continues to fail soft: a transport failure,
non-success status, or unreadable body returns an empty model list. An unused
body on a non-success response is cancelled before returning.

Chat generation retains its existing 120-second deadline. The timer now remains
active while reading either the successful JSON response or the error response
text. A complete non-success response keeps the existing Ollama error result; a
request that reaches the deadline returns the existing timeout result. These
deadlines cover asynchronous network waits. Synchronous JSON parsing and other
CPU work cannot be preempted by the timer.

The `Ollama request deadlines` workflow exercises the production functions with
a temporary HTTP server bound to loopback and synthetic responses. Its fixtures
accelerate only the timer callback while checking the production timeout values
passed to `setTimeout`. They cover held bodies, cancellation, completed and
delayed bodies, network errors, and a successful request after a timeout. They
do not connect to an Ollama installation, execute a model, or measure behavior
of an external provider.

The workflow uses a corrected server lockfile so frozen installation matches
the current package manifest. It removes stale root dependency metadata without
changing the declared package versions.

The deadlines do not bound the full chat operation or synchronous parsing. Model
discovery still treats errors as an empty list, so an empty result does not prove
that no models are installed. The client does not retry timed-out requests or
provide a separate generation-size budget. Hosted-provider behavior is outside
this Ollama-specific contract.

Ryan Wentzel, [ryanwentzel.me](https://ryanwentzel.me)
