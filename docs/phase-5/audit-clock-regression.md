# Synthetic audit clock regression check

Core and Fleet now parse and verify each recorded audit timestamp as an aware
datetime, require timestamps to remain ordered, and reject an API request when
the local clock is earlier than the latest recorded event. Core checks this
before an audited API route runs and again before it appends the event. Fleet
verifies the same condition before catalog reads or changes and immediately
before inserting an audit event. A synthetic test moves the process clock back
to 2020 after a fictional event and confirms that subsequent audit append and
Fleet catalog changes fail closed; normal reads resume when the clock is
restored. The result is a visible 503 through the existing API error handling.

This check anchors the current clock only to prior local events. It cannot
establish that the wall clock is correct before the first event, detect an NTP
source outage by itself, or prove that certificates and tokens remain valid
during a site time failure. A clock jump during an in-flight request may still
occur after Core's preflight check; target operations need a trusted local time
source, monitoring, and an outage/recovery rehearsal. AT-17 and AT-25 stay open
under [B-06](../blockers-and-build-queue.md).
