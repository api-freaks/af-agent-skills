# Long-running jobs

Some operations, currently PDF processing, do not return a result when called.
They accept the job, return a task identifier, and do the work in the
background. The MCP tools cover submitting a job, checking its status, and
retrieving the output; this file covers how to use them without getting stuck or
reporting the wrong outcome.

If any other operation returns a task identifier instead of data, the same rules
apply.

## Accepted is not finished

The first response confirms the job was accepted and names its inputs. It
contains no output. Do not tell the user the work is done at this point; it can
still fail.

## Poll with a ceiling

Check the task's status with a delay between attempts, increasing the delay as
you go, and stop at a sensible total wait. A tight loop does not make the job
finish sooner, and an unbounded one hangs the task if something upstream is
stuck.

If the ceiling is reached, tell the user the job is still running and give them
the task identifier so they can check later.

## A failed job looks like a successful call

This is the most important thing in this file. When a job fails, checking its
status still succeeds: the failure is reported inside the result as a `status`
of `failed`, with an `error` and a `message` explaining why.

So always read the `status` field. An agent that checks only whether the call
succeeded will report success and hand the user nothing.

Pass the `message` to the user as written. It usually names a problem they can
fix and retry, such as a page range beyond the end of the document.

## Retrieve before anything else

Once a job completes, download the output first. Tasks and their outputs carry
an `expiresAt`; after it, the output is gone and the job has to run again, which
costs credits again.

If you hand a task identifier back to the user for later, tell them when it
expires.

Save binary output to a file rather than holding it in memory.

## Webhooks

Where an operation accepts a webhook, the platform calls back on completion
instead of being polled. The tool's description says whether it does.

In an interactive session there is usually nowhere for a callback to land, so
polling with a ceiling is the better choice. Only suggest a webhook to a user who
has a service that can receive one.
