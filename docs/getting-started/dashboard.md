# Dashboard Tour

The JOCKY web dashboard is available at `http://localhost:8080/dashboard/` after starting the server.

---

## Layout

```
┌───────────────────────────────────────────────────────┐
│  JOCKY Enterprise Digital Forensics                   │
├───────────┬───────────────────────────────────────────┤
│           │                                           │
│  Sidebar  │  Main Panel                               │
│           │                                           │
│  Sessions │  (changes based on sidebar selection)     │
│  Compile  │                                           │
│  Approve  │                                           │
│  Audit    │                                           │
│  Settings │                                           │
│           │                                           │
└───────────┴───────────────────────────────────────────┘
```

---

## Sessions Panel

**Create a new session:**
1. Click **New Session**
2. Fill in: Target IP, Warrant ID, Artifact types
3. Click **Create** → session status becomes `PENDING_APPROVAL`

**Session statuses:**

| Status | Meaning |
|--------|---------|
| `PENDING_APPROVAL` | Created, waiting for a second officer to approve |
| `APPROVED` | Countersigned, ready to dispatch |
| `ACTIVE` | Agent is running and sending telemetry |
| `COMPLETED` | Collection finished, agent disconnected |
| `FAILED` | Agent encountered an error |

---

## Compile Panel

Paste or type JOCKY DSL directly in the browser and compile it:

1. Paste your `.jocky` source in the text area.
2. Select target: **Linux** or **Windows**.
3. Click **Compile**.
4. The compiled LLVM IR appears below, with build metadata.
5. Click **Download IR** to save the `.ll` file.

---

## Approve Panel

For dual-control approval:

1. Select a session in `PENDING_APPROVAL` state.
2. Enter your Officer ID (must be different from the creating officer).
3. Click **Approve Session**.
4. Session status changes to `APPROVED`.

---

## Covert Route Panel

For domain-fronting configuration:

1. Select an approved session.
2. Click **Covert Route**.
3. Fill in: Front Domain, Real Host, Backend URL.
4. Toggle **Enable Domain Fronting** on.
5. Click **Configure Route**.
6. The `dial_url` (what the agent will actually connect to) and SNI are shown.

---

## Audit Ledger Panel

Displays the full blockchain ledger in real-time:

- Each block shows: index, timestamp, event type, session ID, hash
- **Verify Chain** button — checks all block hashes, reports OK or tampered
- **Export** button — downloads the full ledger as JSON for court submission

---

## Telemetry Feed

Live WebSocket feed of agent data:

- Connection status indicator
- Incoming telemetry packets (JSON): session ID, event type, payload hash
- Auto-scrolling log
- **Clear** button

---

## Settings Panel

| Setting | Description |
|---------|-------------|
| Server URL | API base URL (default: current origin) |
| Officer ID | Your officer ID for session approval |
| Theme | Light / Dark |
