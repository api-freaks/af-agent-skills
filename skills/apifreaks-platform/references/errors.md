# Handling failures

How to respond when a call fails. This covers the general pattern rather than
listing error codes, because the same code can mean different things on
different endpoints. The tool's own description, or the endpoint's page on
https://apifreaks.com, covers anything specific to it.

## Read the message first

Every error response carries a `message` describing the specific problem, and it
is the only field guaranteed to be present. It usually names the exact missing
parameter, the unsupported input, or the limit reached.

Decide what to do from the message, not from an error code alone. The same code
can mean an account problem on one endpoint and an input problem on another, and
those need opposite responses.

Surface the message to the user as written. A paraphrase loses the detail that
tells them what to fix.

## Is it worth retrying?

Ask what caused the failure, and whether sending the same request again could
possibly change the outcome.

**Never retry unchanged:**

- **Authentication failures.** A bad or missing key fails identically every
  time, and repeated attempts can look like abuse.
- **Invalid input.** A malformed value, a missing required parameter, or an input
  the endpoint does not support. Fix the request or tell the user.
- **Account or billing state.** No credits, an inactive plan, or a role that
  lacks permission. The user resolves these in the dashboard or with their
  organization admin, not the agent.

**Retry with backoff:**

- **Limits reached.** Slow down, reduce parallelism, and try again. These are
  pacing signals rather than failures.
- **Timeouts reaching a remote resource.** Endpoints that fetch from third
  parties can be slowed by the far side. Once or twice is reasonable.
- **Server-side faults.** Retry a few times with increasing delay, then check
  https://status.apifreaks.com/ and stop, so a platform incident is not
  mistaken for a problem with the user's setup.

**Retry differently:**

- **Too large.** Split the batch or reduce the input and send the parts.
- **Processing took too long.** The same input will fail the same way. Send less.

## Never loop without a ceiling

Cap retries, increase the delay between attempts, and stop when the cap is
reached. An unbounded retry loop turns a transient problem into a hung task.

## Failures are free

Only successful calls are billed. A failed call deducts nothing, and anything
already charged is refunded. So a failure costs time rather than credits, and
there is no billing reason to avoid a retry that is actually warranted.

## Some failures look like successes

Checking only whether the call succeeded misses these:

- **A background job that failed** reports it inside the result.
- **A negative answer** can be a successful, billed call.
- **Partial success** returns what worked and describes what did not.

Read the result before reporting any outcome.

## Where to send the user

For account, billing, or permission problems: the dashboard at
https://apifreaks.com, or their organization admin if they are in one. For
anything else that persists: https://apifreaks.com/contact
