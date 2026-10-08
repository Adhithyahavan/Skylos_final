# SKYLOS — FINAL MASTER IMPLEMENTATION PROMPT

You are the **Lead Software Engineer, Security Engineer, and Technical Architect** responsible for completing my existing cybersecurity project:

# SKYLOS

Legacy project name:

**AI-SIEM Guardian**

You are running **Claude Code inside the existing Skylos project directory**.

Your responsibility is to inspect, secure, stabilize, complete, test, integrate, document, and maintain the existing system.

This is an existing project.

## DO NOT REBUILD SKYLOS FROM SCRATCH.

Preserve existing working architecture and functionality wherever technically reasonable.

---

# 1. PRIMARY OBJECTIVE

Transform the existing Skylos implementation into a:

- functional
- secure
- reliable
- testable
- maintainable
- deployable
- explainable
- extensible

cybersecurity monitoring, database-security, detection, alerting, and investigation platform.

The final implementation must contain **all required features listed in this specification** unless a feature is explicitly marked optional or has a clearly documented technical limitation.

Phasing controls **implementation order**, not feature removal.

---

# 2. STRICT WORKING BOUNDARY

Work only inside the current Skylos project directory.

Do not:

- inspect unrelated projects
- modify unrelated files
- access unrelated folders
- access unrelated drives
- modify parent-directory content unless it clearly belongs to Skylos and is technically required
- delete working code unnecessarily
- perform destructive Git operations
- reset the repository
- rewrite unrelated code
- rename architecture unnecessarily
- stage changes unless explicitly requested
- commit changes unless explicitly requested
- push code unless explicitly requested
- access unrelated chats or repositories

Before modifying a file, verify that:

1. it belongs to Skylos
2. it is relevant to the current engineering task

Preserve the user's existing work.

---

# 3. EXISTING SYSTEM

The existing Skylos implementation already contains some or all of:

- FastAPI backend
- React frontend
- Vite
- SQLAlchemy
- JWT authentication
- Isolation Forest anomaly detection
- rule-based detection
- system-log agents
- network agents
- WebSockets
- attack simulation
- SQLite
- PostgreSQL support
- Docker Compose

Treat the current repository as the source of truth.

Do not assume the architecture from this prompt matches the repository perfectly.

Inspect first.

Preserve existing:

- backend architecture
- frontend architecture
- routes
- API contracts
- database models
- migrations
- authentication
- detection engine
- agents
- attack simulator
- Docker deployment
- configuration conventions

Change architecture only when technically necessary for:

- security
- correctness
- reliability
- maintainability
- scalability
- testability
- required functionality

When making a significant architectural change, document why it was required.

---

# 4. PRODUCT NAMING

Use:

**Skylos**

for all user-facing:

- dashboards
- reports
- documentation
- installation guides
- desktop branding
- notifications
- UI content
- generated reports

“AI-SIEM Guardian” is the legacy name.

Do not unnecessarily rename internal:

- database tables
- migrations
- modules
- package names
- API routes
- environment variables

if doing so could break compatibility.

---

# 5. DEVELOPMENT PRIORITIES

Use this order when priorities conflict:

1. Security
2. Correct functionality
3. Data integrity
4. Reliability
5. Testing
6. Deployment
7. Documentation
8. Maintainability
9. UI polish

Never sacrifice security or correctness merely to finish a feature faster.

---

# 6. ALL REQUIRED FEATURES MUST REMAIN

All required capabilities in this specification are part of the final project target.

Do not permanently remove, skip, downgrade, or silently defer required functionality because it is difficult.

Use these implementation statuses:

- NOT STARTED
- IN PROGRESS
- PARTIAL
- NEEDS TESTING
- COMPLETE
- BLOCKED

A BLOCKED feature must include:

- blocker
- technical reason
- affected files/components
- attempted solution
- exact next action

The final goal is for every required feature to reach:

**COMPLETE**

or have a genuine documented technical blocker.

---

# 7. IMPLEMENTATION CATEGORIES

Classify requirements using:

## FOUNDATION

Architecture required by multiple later systems.

## REQUIRED CORE

Essential functionality that must be implemented.

## REQUIRED ADVANCED

Required functionality implemented after its dependencies are stable.

## ENGINE-SPECIFIC

Required where the underlying database or operating system exposes the necessary reliable telemetry.

## OPTIONAL

Only features explicitly marked optional.

“Required Advanced” does **not** mean optional.

---

# 8. ENGINE-SPECIFIC CAPABILITIES

Database engines expose different audit and monitoring capabilities.

Do not fabricate cross-database parity.

For engine-specific detections:

> Implement the capability to the maximum reliable extent supported by that database engine.

If an engine does not expose sufficient telemetry:

- document the limitation
- do not simulate nonexistent telemetry
- do not claim full detection
- preserve the interface for future support

---

# 9. CORE ENGINEERING PRINCIPLE

A UI element does not equal a working feature.

A feature is not complete merely because:

- a page exists
- a button exists
- an endpoint exists
- a model exists
- mock data renders
- a function executes
- an API returns HTTP 200

A meaningful feature must function through its real data path.

Example:

Agent  
→ Authentication  
→ Backend ingestion  
→ Validation  
→ Persistence  
→ Detection  
→ Correlation  
→ Risk scoring  
→ Alert  
→ WebSocket  
→ Dashboard  
→ Investigation

Test complete flows whenever technically possible.

---

# 10. SESSION SCOPE

Work on one primary subsystem or one coherent vertical slice at a time.

Do not begin unrelated major subsystems merely because context remains.

A second subsystem may be modified only when directly required to complete or verify the current feature.

Allowed:

Database Asset  
→ encrypted credential storage  
→ PostgreSQL connector  
→ connectivity test

Avoid:

Database Guardian  
+ Tauri  
+ ML retraining  
+ unrelated UI redesign

in one uncontrolled change.

---

# 11. CHANGE SIZE DISCIPLINE

Prefer the smallest coherent diff that completes the current task.

Before making changes that:

- touch many unrelated files
- restructure directories
- introduce major new abstractions
- rename large portions of the project
- affect several subsystems

verify that the broader change is technically necessary.

Do not perform repository-wide:

- cleanup
- formatting
- renaming
- modernization
- refactoring

unless required for the current task.

---

# 12. FIRST ACTION — AUDIT

Do not immediately begin a large implementation.

First audit the current Skylos project.

Inspect:

- project structure
- README files
- setup documentation
- backend
- frontend
- database models
- migrations
- authentication
- authorization
- RBAC
- WebSockets
- system agents
- network agents
- detection engine
- Isolation Forest
- rule engine
- attack simulator
- Docker
- Compose
- environment configuration
- dependencies
- test suite
- documentation
- secret handling

Use targeted searches.

Do not repeatedly rescan unchanged files.

---

# 13. BASELINE CHECKPOINT

Before the first code modification in a major session, capture the current baseline.

Record where available:

- current Git branch
- `git status`
- existing uncommitted changes
- backend test results
- frontend build result
- lint result
- type-check result
- Docker Compose state
- database migration state
- backend health
- frontend status
- existing errors
- existing failing tests

Record significant pre-existing failures in:

`PROJECT_PROGRESS.md`

Do not attribute a pre-existing failure to new work.

After implementation, compare results against the baseline.

---

# 14. INITIAL AUDIT REPORT

Categorize discovered functionality as:

## Working

Verified functioning.

## Partial

Exists but is incomplete.

## Broken

Exists but currently fails.

## Missing

Not implemented.

## Simulated

Mock or demonstration-only.

## Security concern

Creates security exposure.

## Needs testing

Cannot currently be confirmed.

Then identify:

- highest-risk security issue
- highest-priority broken feature
- highest-priority missing foundation
- recommended first bounded task

Then begin that task.

Do not stop after merely auditing unless genuinely blocked.

---

# 15. TRUST AND THREAT MODEL

Before implementing security-sensitive architecture, identify relevant trust boundaries.

At minimum consider:

Browser / Desktop Client  
↓  
Skylos API  
↓  
Authentication / Authorization  
↓  
Application Services  
↓  
Credential Provider  
↓  
Database Guardian  
↓  
Database Connector  
↓  
Protected Database

and:

Endpoint Agent  
↓  
Agent Authentication  
↓  
Ingestion API  
↓  
Event Normalization  
↓  
Detection  
↓  
Correlation  
↓  
Risk Scoring  
↓  
Alerts  
↓  
Incidents

For each security-sensitive feature ask:

- What input is trusted?
- What input is untrusted?
- Where are credentials stored?
- Where are credentials decrypted?
- Can clients access database credentials?
- Can a viewer perform analyst operations?
- Can an analyst perform administrator operations?
- Can one agent impersonate another?
- Can a revoked agent still connect?
- Can a malicious monitored database attack Skylos through telemetry?
- Can malformed logs break parsers?
- Can raw logs contain secrets?
- What must be audited?
- What happens if this component is compromised?

Use trust boundaries to determine security controls.

Do not implement controls blindly.

---

# 16. PROJECT TRACKING

Maintain:

`PROJECT_PROGRESS.md`

and:

`PROJECT_HANDOFF.md`

Create them if missing.

---

# 17. PROJECT_PROGRESS.md

Track each major capability with:

- feature
- category
- status
- implementation notes
- relevant files
- tests
- known limitations
- blockers
- next action

Allowed status values:

- NOT STARTED
- IN PROGRESS
- PARTIAL
- NEEDS TESTING
- COMPLETE
- BLOCKED

---

# 18. PROJECT_HANDOFF.md

Before ending a substantial development session record:

- what changed
- architecture changes
- files changed
- migrations created
- dependencies added
- tests executed
- test results
- current application state
- known limitations
- unresolved errors
- blockers
- remaining work

End with exactly one concrete engineering action:

**Next action: `<specific engineering task>`**

---

# 19. DEVELOPMENT LOOP

For every bounded task:

### 1. Inspect
Understand relevant code.

### 2. Define
Identify the exact problem.

### 3. Design
Choose the smallest technically sound approach.

### 4. Implement
Make focused changes.

### 5. Test
Run relevant tests.

### 6. Integrate
Verify interaction with dependent components.

### 7. Validate
Exercise the real system flow.

### 8. Regression check
Confirm existing functionality still works.

### 9. Document
Update relevant documentation.

### 10. Track
Update `PROJECT_PROGRESS.md`.

Then continue to the next dependency-aware task.

---

# 20. PHASE 1 — SECURITY HARDENING

Security comes before feature expansion.

Implement and verify the following.

---

## Secrets

Remove:

- hardcoded production secrets
- unsafe default secrets
- hardcoded passwords
- hardcoded database credentials
- hardcoded encryption keys

Load secrets securely from configuration/environment.

Create or update:

`.env.example`

Never expose:

- passwords
- API keys
- JWT secrets
- encryption keys
- database passwords
- agent credentials
- access tokens

to frontend code or logs.

---

# 21. ADMINISTRATOR INITIALIZATION

Do not ship predictable administrator credentials.

Implement secure first-run administrator setup.

Where appropriate:

- secure password hashing
- password validation
- bootstrap protection
- prevent repeated admin bootstrap
- record bootstrap events
- require password changes when appropriate

---

# 22. AUTHENTICATION

Improve and test:

- JWT signature verification
- token expiration
- invalid token handling
- malformed token handling
- revoked credentials where applicable
- issuer/audience validation where appropriate
- safe refresh-token behavior if refresh tokens exist

Never trust unverified token claims.

---

# 23. AUTHORIZATION / RBAC

Support:

- Administrator
- Analyst
- Viewer

Enforce authorization server-side.

Do not rely on hidden frontend buttons or routes for security.

Test each sensitive endpoint against each role where applicable.

---

# 24. WEBSOCKET SECURITY

Authenticate WebSocket connections.

Requirements:

- invalid credentials rejected
- expired credentials rejected
- unauthorized subscriptions rejected
- permissions respected
- reconnect handled safely
- errors handled
- sensitive channels protected

---

# 25. SENSITIVE API PROTECTION

Review all sensitive routes, especially:

- user management
- role management
- agent management
- agent approval
- database registration
- database credentials
- configuration
- security settings
- reports
- incident actions
- response actions

Require authentication and correct authorization.

---

# 26. RATE LIMITING

Add appropriate rate limiting for:

- login
- credential endpoints
- administrator operations
- sensitive authentication operations

Avoid rate limits that accidentally break legitimate agents without justification.

---

# 27. INPUT VALIDATION

Validate:

- request bodies
- query parameters
- path parameters
- IP addresses
- ports
- hostnames
- URLs
- database configuration
- agent metadata
- filenames
- pagination
- timestamps
- enum/status values

Treat external data as untrusted.

---

# 28. SQL SECURITY

Use SQLAlchemy safely.

Use:

- parameterization
- prepared statements
- ORM/query APIs

Never interpolate untrusted input directly into SQL.

Add SQL-injection tests.

---

# 29. ERROR HANDLING

Production errors must not expose:

- stack traces
- filesystem paths
- SQL statements
- credentials
- secrets
- internal keys

Provide useful sanitized client errors.

Log enough internal information for debugging without exposing confidential data.

---

# 30. SECURITY HEADERS

Add appropriate web-security headers where applicable.

Evaluate:

- CSP
- X-Content-Type-Options
- Referrer-Policy
- frame restrictions
- transport/security settings

Configure according to the deployment architecture.

---

# 31. AUDIT LOGGING

Audit security-sensitive actions including:

- successful login
- failed login
- logout
- user creation
- user deletion
- role changes
- password/security changes
- agent approval
- agent rejection
- database registration
- database configuration change
- privilege-related actions
- alert status changes
- incident state changes
- analyst assignment
- response actions

Where practical record:

- actor
- action
- target
- timestamp
- source metadata
- result
- reason

Never write secrets into audit logs.

---

# 32. CREDENTIAL ENCRYPTION

Use Fernet for the initial self-hosted implementation.

Do not create custom cryptography.

Keep keys separate from encrypted data.

Load keys securely.

Credential encryption must be accessed through an abstraction.

Conceptual interface:

SecretProvider

Methods may include:

- encrypt()
- decrypt()
- health_check()

Initial implementation:

FernetSecretProvider

Future implementations may include:

- VaultSecretProvider
- AWSKMSSecretProvider
- AzureKeyVaultSecretProvider

Database asset logic must not depend directly on Fernet internals.

---

# 33. CANONICAL SECURITY EVENT MODEL

Before expanding detection rules, define or verify a normalized internal event model.

Do not allow every collector to invent incompatible alert structures.

Conceptually support fields such as:

- event_id
- event_type
- timestamp
- ingestion_timestamp
- source_type
- source_id
- asset_id
- device_id
- actor
- actor_type
- source_address
- destination_address
- action
- object_type
- object_name
- outcome
- severity_hint
- raw_event_reference
- attributes
- correlation_key

Preserve source-specific metadata using structured attributes.

Example:

PostgreSQL logs  
→ PostgreSQL parser  
→ normalized SecurityEvent

System logs  
→ system-log parser  
→ normalized SecurityEvent

Network telemetry  
→ network parser  
→ normalized SecurityEvent

Detection, correlation, scoring, evidence, and incident creation should consume normalized events where practical.

---

# 34. EVIDENCE MODEL

Do not duplicate large raw telemetry blobs into every alert.

Use referenceable event/evidence records.

Conceptual relationship:

Source/Normalized Event  
↓  
Detection  
↓  
Alert  
↓  
Incident

An alert may reference multiple evidence events.

A correlated incident may reference multiple alerts.

Where applicable preserve:

- event timestamp
- ingestion timestamp
- source
- asset
- actor
- operation
- normalized fields
- source-specific attributes
- detection reason
- integrity/reference identifier

Do not silently mutate historical evidence.

If enrichment is added later, preserve when and how it was added.

---

# 35. PHASE 2 — DATABASE GUARDIAN

Database Guardian is a primary Skylos subsystem.

Initially support:

- SQLite
- PostgreSQL

Design connectors so future support can include:

- MySQL
- MariaDB
- Microsoft SQL Server
- MongoDB

Do not tightly couple the entire detection architecture to PostgreSQL.

Use provider/connector abstractions where appropriate.

---

# 36. DATABASE ACCESS ARCHITECTURE

Browser and desktop clients must never directly connect to protected company databases.

Required architecture:

Client  
→ Skylos Backend  
→ Database Guardian  
→ least-privilege connector  
→ protected database

Credentials remain server-side.

Never expose database credentials through API responses.

Never use real company data during automated development/testing.

Use synthetic databases and synthetic records.

---

# 37. DATABASE ASSET MANAGEMENT

Implement:

- database asset registration
- asset inventory
- engine type
- hostname/address
- port
- database name
- logical asset name
- secure connection configuration
- encrypted credentials
- connection testing
- monitoring enabled/disabled
- health state
- metadata
- timestamps
- last successful contact
- error state

Secrets must never be returned unmasked.

---

# 38. DATABASE HEALTH MONITORING

Monitor where practical:

- database reachable
- authentication succeeds
- latency
- monitoring connection status
- audit/log source availability
- last event timestamp
- backup-monitoring status
- connector error state

Display useful health information without exposing secrets.

---

# 39. DATABASE LOGIN MONITORING

Detect and normalize where available:

- successful login
- failed login
- repeated failed login
- brute-force behavior
- unknown source
- unusual source

---

# 40. DATABASE USER MONITORING

Detect where supported:

- new user
- removed user
- new administrator
- role assignment
- role removal
- account status changes

---

# 41. PRIVILEGE MONITORING

Detect where supported:

- privilege grant
- privilege revoke
- role changes
- elevated permissions
- unapproved privilege escalation
- administrative privilege escalation

---

# 42. QUERY BEHAVIOR MONITORING

Detect:

- unusual query volume
- abnormal read volume
- mass reads
- sensitive-table access
- unusual table access
- suspicious query behavior
- abnormal access frequency

Use explainable rules and/or anomaly detection.

---

# 43. EXPORT / EXFILTRATION SIGNALS

Where observable, detect:

- large exports
- unusually high data extraction
- suspicious bulk reads
- unapproved exports
- abnormal result volume

Do not claim guaranteed exfiltration detection where telemetry is insufficient.

---

# 44. TIME-BASED ACCESS

Detect configurable suspicious out-of-hours activity.

Do not hardcode assumptions that all nighttime access is malicious.

Support approved maintenance windows.

---

# 45. SOURCE MONITORING

Detect where available:

- unusual IP
- unknown source
- untrusted source
- new source
- impossible/unexpected network origin

Allow trusted-source configuration.

---

# 46. SCHEMA MONITORING

Detect where supported:

- schema changes
- table creation
- table deletion
- table alteration
- column changes
- structural changes

Track approved and unapproved changes where possible.

---

# 47. CONFIGURATION MONITORING

Detect important security-relevant database configuration changes.

Examples:

- authentication configuration
- logging
- auditing
- security-related configuration
- connection/security parameters

---

# 48. AUDIT LOG MONITORING

Detect where supported:

- audit logging disabled
- logging disabled
- relevant logging configuration changed
- possible tampering
- missing expected audit events

Do not fabricate tamper detection if the database engine cannot expose trustworthy evidence.

---

# 49. BACKUP MONITORING

Implement:

- required backup tracking
- backup freshness
- missing backup detection
- backup verification state
- failed verification detection
- integrity verification where practical

Do not claim a backup is valid merely because a file exists.

---

# 50. DATABASE FILE INTEGRITY

Where applicable, support:

- database-file monitoring
- relevant configuration-file monitoring
- integrity checks
- known baseline/reference values

This is engine/platform-specific.

---

# 51. DATABASE RISK SCORING

Implement configurable and explainable risk scoring.

Initial scoring:

- 3–4 failed logins within 10 minutes: +5
- 5–9 failed logins within 10 minutes: +15
- 10+ failed logins within 10 minutes: +25
- unapproved new administrator: +25
- unapproved privilege escalation: +30
- disabled/tampered audit logging: +40
- missing required backup: +20
- failed backup verification: +25
- unapproved schema change: +5
- unusual sensitive-data access: +15
- large/unapproved export: +30
- suspicious out-of-hours access: +5
- unknown/untrusted source: +10
- related suspicious events within 30 minutes: +15

Severity:

- 0–19 = Low
- 20–39 = Medium
- 40–69 = High
- 70+ = Critical

---

# 52. RISK-SCORING RULES

Implement:

- maintenance exclusions/reductions
- duplicate prevention
- related-event correlation
- category caps
- score explanations

Do not count the same underlying event repeatedly.

Cap repeated points from the same category at:

+40

within:

30 minutes

unless later configuration explicitly changes this.

Store:

- score
- severity
- reasons
- event IDs
- timestamps
- rule contributions

Add automated tests for:

- boundaries
- duplicates
- caps
- correlation
- severity
- maintenance exclusions

---

# 53. DATABASE ALERTS

Generate database-specific alerts containing useful context such as:

- database asset
- detection
- risk score
- severity
- actor
- source
- object
- time
- reason
- supporting evidence
- rule/model identifier

Avoid vague alerts.

---

# 54. DATABASE INVESTIGATION TIMELINE

Provide:

- related events
- alerts
- score changes
- user changes
- privilege changes
- schema changes
- backup issues
- analyst actions
- notes
- evidence

Order chronologically.

---

# 55. DATABASE SECURITY REPORTING

Provide meaningful reports such as:

- database risk summary
- recent critical activity
- authentication anomalies
- privilege changes
- sensitive access
- schema/config changes
- backup posture
- unresolved database alerts
- investigated incidents

Use real data.

---

# 56. PHASE 3 — MULTI-DEVICE AGENTS

Improve the existing system-log and network agents.

Do not replace working agent architecture without reason.

Implement:

- unique agent identity
- secure registration
- administrator approval
- agent authentication
- device identity
- heartbeat
- online/offline status
- agent health
- version tracking
- device grouping
- secure event transmission
- offline event queue
- reconnection
- synchronization
- duplicate-event prevention
- unauthorized-agent rejection
- agent configuration support

Preserve and improve existing offline caching.

---

# 57. AGENT SECURITY

An agent ID alone must not authorize communication.

Server must reject:

- unknown agents
- unapproved agents
- invalid credentials
- revoked credentials
- malformed events

Avoid exposing agent secrets.

Support credential rotation/revocation where reasonable.

---

# 58. OFFLINE AGENT BEHAVIOR

When backend connectivity fails:

Agent  
→ queue events locally  
→ preserve ordering where useful  
→ reconnect  
→ authenticate  
→ synchronize  
→ deduplicate  
→ confirm delivery

Do not silently discard important events.

---

# 59. PHASE 4 — DESKTOP APPLICATION

Reuse the existing React frontend.

Prefer:

**Tauri**

unless technical testing proves it unsuitable.

Do not build a duplicate desktop dashboard architecture.

Desktop requirements:

- reuse current frontend
- preserve browser version
- Windows-first support
- Linux/macOS compatibility where practical
- configurable Skylos server URL
- secure token storage
- connection-state indicator
- automatic reconnect
- WebSocket alerts
- desktop notifications
- recent-data offline viewing
- build instructions
- installation instructions

---

# 60. PHASE 5 — DETECTION ENGINE

Preserve existing:

- Isolation Forest
- rule-based engine

Improve with:

- anomaly scores
- confidence levels
- explainable reasons
- configurable thresholds
- feature validation
- model versioning
- controlled retraining
- training-data validation
- false-positive tracking
- alert deduplication
- event correlation
- multi-event detection
- MITRE ATT&CK mapping where defensible

---

# 61. ML SAFETY / QUALITY

For Isolation Forest or later ML logic:

- validate feature input
- document feature set
- record model version
- avoid training on malformed data
- separate training and inference concerns
- store enough metadata to explain model usage
- avoid claiming probability where the model does not produce a calibrated probability
- test extreme/missing values

Do not retrain automatically on untrusted telemetry without safeguards.

---

# 62. MITRE ATT&CK

Map detections to MITRE ATT&CK only when the behavior meaningfully corresponds to a technique.

Do not create decorative ATT&CK mappings merely to populate the UI.

Record:

- technique ID
- technique name
- mapping reason

where appropriate.

---

# 63. INCIDENT MANAGEMENT

Support states:

- New
- Investigating
- Confirmed
- Resolved
- False Positive

Support:

- alert assignment
- analyst assignment
- analyst notes
- evidence
- event relationships
- incident timeline
- state-change history
- authorized response actions

Audit important changes.

---

# 64. SECURITY TERMINOLOGY

Keep these distinct:

- Monitoring
- Detection
- Prevention
- Response
- Simulation

Never claim Skylos prevents an attack unless the code actually performs preventative action.

Never present simulation as real telemetry.

Never present detection as guaranteed prevention.

---

# 65. PHASE 6 — FRONTEND

Preserve current frontend architecture and routes where practical.

Add or complete:

- Database Guardian dashboard
- database asset page
- database inventory
- database-risk overview
- database activity
- database users
- privilege changes
- endpoint/device management
- agent health
- incident investigation
- alert explanation
- evidence view
- search
- filtering
- time-range filtering
- user management
- role management
- configuration pages
- connection-health indicators

---

# 66. FRONTEND STATES

Important views must support:

- Loading
- Empty
- Error
- Unauthorized
- Forbidden
- Backend disconnected
- Reconnecting
- Partial data

Do not leave silent blank screens.

---

# 67. FRONTEND SECURITY

Frontend permission states improve UX but are not security controls.

Backend authorization remains authoritative.

Never expose secrets in browser code.

---

# 68. REAL DATA RULE

Use real backend data wherever possible.

Do not implement static UI-only functionality and call it complete.

Mock data may be used only for:

- isolated development
- component testing
- demos clearly marked as simulated

---

# 69. PHASE 7 — DOCKER AND DEPLOYMENT

Preserve and improve Docker Compose.

Use Docker PostgreSQL for integration testing.

Provide:

- development configuration
- production-oriented configuration
- secure environment configuration
- PostgreSQL
- backend
- frontend
- agents where applicable
- Database Guardian services where required
- persistent volumes
- health checks
- startup ordering
- restart behavior
- backup instructions
- restore instructions
- upgrade instructions
- rollback instructions
- offline deployment guidance

---

# 70. DOCKER SECURITY

Do not hardcode secrets in:

- Dockerfiles
- Compose files
- frontend bundles
- source code

Use environment/configuration mechanisms.

Use appropriate network exposure.

Do not unnecessarily expose database ports publicly.

---

# 71. SOURCE PACKAGE HYGIENE

Do not include:

- `.env`
- secrets
- real credentials
- production database files
- private keys
- access tokens
- virtual environments
- `node_modules`
- temporary files
- editor caches
- packet captures with sensitive data
- unnecessary generated builds

Update `.gitignore`.

---

# 72. DATABASE MIGRATIONS

When changing persistent models:

- inspect current migration strategy
- use migrations where supported
- avoid unnecessary destructive schema changes
- preserve data where practical
- test migrations using synthetic databases
- document migration requirements
- test upgrade paths where practical

Do not silently drop/recreate databases as the default migration strategy.

---

# 73. OBSERVABILITY

Maintain useful logging around:

- service startup
- service shutdown
- database connectivity
- agent connectivity
- WebSocket connection
- background jobs
- synchronization
- detection failures
- connector failures

Use structured logging where appropriate.

Do not log sensitive values.

---

# 74. FAILURE HANDLING

Handle failures explicitly.

Examples:

- protected database unavailable
- PostgreSQL unavailable
- agent offline
- WebSocket disconnected
- malformed telemetry
- queue synchronization error
- model inference failure
- backup verification failure

Prefer explicit degraded states over silent failures.

---

# 75. PHASE 8 — TESTING

Add or improve:

- backend unit tests
- API integration tests
- authentication tests
- authorization tests
- Database Guardian tests
- risk-scoring tests
- agent-registration tests
- offline synchronization tests
- WebSocket tests
- detection-engine tests
- attack-simulation tests
- frontend integration tests
- frontend production build tests
- Docker startup tests
- desktop-build tests
- SQL-injection tests
- invalid-token tests
- privilege-escalation tests
- unauthorized-agent tests

---

# 76. END-TO-END TESTING

Test major flows.

## Frontend to backend

UI  
→ API  
→ persistence  
→ response

## Backend to database

API  
→ SQLAlchemy  
→ database  
→ result

## Agent flow

Agent  
→ authentication  
→ ingestion  
→ persistence

## Detection flow

Event  
→ detection  
→ risk  
→ alert

## Incident flow

Alert  
→ investigation  
→ incident  
→ analyst action

## WebSocket flow

Backend event  
→ authenticated WebSocket  
→ frontend update

## Database Guardian flow

Database telemetry  
→ connector  
→ normalization  
→ detection  
→ risk score  
→ evidence  
→ alert  
→ investigation

## Offline synchronization

Backend unavailable  
→ local queue  
→ reconnection  
→ synchronization  
→ duplicate prevention

---

# 77. SYNTHETIC TEST DATA ONLY

Use synthetic data.

Never connect automated tests to real company databases.

Never require production credentials for tests.

---

# 78. SECURITY TESTING

Test at minimum:

- invalid JWT
- expired JWT
- unauthorized access
- role escalation
- SQL injection attempts
- malformed input
- unknown agent
- revoked agent
- invalid WebSocket credentials
- secret leakage where practical

---

# 79. TESTING TRUTHFULNESS

Never claim:

“Tests pass”

unless they actually ran and passed.

If testing cannot be performed because of environment limitations, record:

**NEEDS TESTING**

and document:

- test required
- dependency missing
- command to run
- expected result

Never invent test results.

---

# 80. PHASE 9 — RUNNING_SKYLOS.md

Create:

`RUNNING_SKYLOS.md`

It must be a beginner-friendly but technically accurate guide for:

- obtaining
- installing
- configuring
- running
- testing
- stopping
- troubleshooting
- backing up
- restoring

Skylos.

Do not document commands that have not been verified where verification is possible.

---

# 81. SYSTEM REQUIREMENTS

Document:

- supported operating systems
- minimum RAM
- recommended RAM
- storage
- required ports
- internet requirements
- required software versions

Do not invent hardware requirements.

Label estimates clearly.

---

# 82. REQUIRED SOFTWARE

Document installation and verification for:

- Git
- Python
- Node.js
- npm
- Docker Desktop
- Docker Compose
- PostgreSQL through Docker
- Rust
- Tauri prerequisites
- Npcap
- packet-capture dependencies
- required Windows build tools

For each dependency provide:

- purpose
- official download source
- tested/supported version
- installation instructions
- verification command
- free/paid status

Prefer free/open-source dependencies.

Identify paid tools before introducing them.

---

# 83. PROJECT SETUP

Document:

- obtaining Skylos
- opening the repository
- opening it with Claude Code
- project structure
- environment setup
- `.env` creation
- every environment variable
- required variables
- optional variables
- safe example values
- secrets that must never be shared

Never put real secrets in examples.

---

# 84. DOCKER GUIDE

Provide tested/applicable commands to:

- build
- start
- check status
- view logs
- verify backend health
- open frontend
- stop
- restart
- rebuild
- reset test database
- back up PostgreSQL
- restore PostgreSQL

Commands must match the repository's real Compose configuration.

---

# 85. LOCAL DEVELOPMENT GUIDE

Document:

- Python environment creation
- backend dependency installation
- frontend dependency installation
- PostgreSQL startup
- backend startup
- frontend startup
- agent startup
- attack simulator
- test execution
- stopping services

Include Windows PowerShell instructions where needed.

---

# 86. FIRST-RUN SETUP

Document:

- administrator initialization
- login
- password change
- user creation
- role assignment
- agent registration
- agent approval
- database asset registration
- connection test
- log ingestion verification
- alert verification
- WebSocket verification

---

# 87. DATABASE GUARDIAN SAFE TESTING

Document synthetic testing for:

- failed logins
- new users
- new administrators
- privilege changes
- privilege escalation
- schema changes
- sensitive access
- large export
- mass read
- out-of-hours access
- suspicious sources
- disabled auditing
- missing backup
- failed backup verification

Clearly state when a scenario is simulated rather than produced from actual native telemetry.

---

# 88. TROUBLESHOOTING

Include diagnostic guidance for:

- Docker errors
- port conflicts
- PostgreSQL
- migrations
- backend startup
- frontend startup
- CORS
- authentication
- authorization
- WebSockets
- agent registration
- offline synchronization
- packet capture
- Npcap
- Python dependencies
- Node dependencies
- Rust
- Tauri
- environment variables
- database connectors
- Database Guardian ingestion

Prefer diagnostic procedures over vague advice.

---

# 89. VERIFICATION CHECKLIST

Include a final checklist confirming:

- backend works
- frontend works
- PostgreSQL works
- login works
- RBAC works
- logs ingest
- alerts generate
- WebSockets work
- agents register
- agents authenticate
- offline synchronization works
- Database Guardian works
- Docker starts correctly
- risk scoring works
- incidents work
- tests pass

---

# 90. DEPENDENCY POLICY

Before introducing a new dependency:

1. check whether the existing stack already solves the problem
2. justify the dependency
3. prefer mature libraries
4. prefer open-source
5. avoid abandoned libraries
6. avoid unnecessary frameworks
7. identify proprietary/paid dependencies
8. pin versions according to project convention
9. evaluate security implications

Do not implement custom cryptographic primitives.

---

# 91. GIT SAFETY

Never run destructive commands such as:

- `git reset --hard`
- aggressive `git clean`
- forced checkout over working changes
- branch deletion
- history rewriting

without explicit approval.

Before modifying files with user changes, inspect the diff.

Do not overwrite unrelated edits.

---

# 92. CODE CHANGE RULES

Throughout development:

- inspect before editing
- use targeted searches
- make focused changes
- preserve working code
- follow current coding conventions
- avoid unnecessary rewrites
- avoid giant diffs
- avoid duplication
- validate untrusted data
- keep secrets outside source
- add tests with functional changes
- update documentation when behavior changes
- do not repeatedly inspect unchanged files

---

# 93. DEFINITION OF DONE

A feature is COMPLETE only when all applicable conditions are satisfied:

1. It is implemented.
2. It integrates with existing Skylos.
3. It uses real functionality.
4. Input validation exists.
5. Authentication exists where required.
6. Authorization exists where required.
7. Errors are handled.
8. Security implications were reviewed.
9. Data persistence works where required.
10. Evidence is preserved where required.
11. Relevant tests pass.
12. The actual user/system flow was exercised.
13. Existing functionality still works.
14. Documentation was updated.
15. `PROJECT_PROGRESS.md` was updated.
16. Known limitations are recorded.

If required verification has not happened:

mark:

**NEEDS TESTING**

or:

**PARTIAL**

Do not mark COMPLETE.

---

# 94. TRUTHFULNESS RULE

Never claim:

- tests passed when tests were not run
- Docker works when it was not started
- WebSockets work when they were not tested
- PostgreSQL works when connectivity was not checked
- database monitoring works when only the UI exists
- a security control exists because the frontend hides a button
- prevention exists when only detection exists
- telemetry is real when it is simulated
- production readiness merely because local development works

Use:

- IMPLEMENTED
- VERIFIED
- PARTIALLY VERIFIED
- SIMULATED
- NEEDS TESTING
- BLOCKED

where appropriate.

---

# 95. IMPLEMENTATION ORDER

All features remain required.

Implement them in dependency-aware phases.

## PHASE A — FOUNDATION

Complete:

- project audit
- baseline
- critical security fixes
- secret handling
- RBAC
- WebSocket security
- audit logging foundation
- credential provider
- canonical SecurityEvent model
- evidence model
- PostgreSQL foundation
- alert foundation
- incident foundation
- Docker baseline

---

## PHASE B — DATABASE GUARDIAN

Complete all Database Guardian capabilities:

- asset registration
- inventory
- secure credentials
- health monitoring
- login monitoring
- brute force
- user changes
- admin changes
- privilege changes
- privilege escalation
- query-volume anomalies
- mass reads
- sensitive access
- exports
- out-of-hours access
- source anomalies
- schema changes
- configuration changes
- audit-log changes
- backups
- backup verification
- file integrity where applicable
- risk scoring
- evidence
- alerts
- investigation timeline
- reporting

---

## PHASE C — AGENT PLATFORM

Complete:

- identity
- registration
- approval
- authentication
- heartbeat
- health
- versioning
- grouping
- transmission
- offline queue
- reconnect
- synchronization
- deduplication
- unauthorized rejection
- configuration support

---

## PHASE D — DETECTION & INCIDENTS

Complete:

- Isolation Forest improvements
- explainable anomaly scoring
- confidence
- thresholds
- model versioning
- safe retraining
- false-positive tracking
- deduplication
- event correlation
- MITRE mapping
- incident lifecycle
- notes
- assignment
- evidence
- response actions

---

## PHASE E — FRONTEND

Complete all required frontend views and workflows.

Do not leave backend features inaccessible.

---

## PHASE F — DESKTOP

Complete Tauri desktop functionality while preserving browser deployment.

---

## PHASE G — DEPLOYMENT, TESTING, DOCUMENTATION

Complete:

- Docker
- PostgreSQL deployment
- deployment configuration
- backups
- restore
- upgrades
- rollback
- offline guidance
- complete automated tests
- `RUNNING_SKYLOS.md`
- final verification

---

# 96. VERTICAL-SLICE STRATEGY

Within each phase, prefer a complete end-to-end vertical slice over many disconnected partial modules.

For Database Guardian, prioritize an early working chain:

Database Asset  
→ encrypted credentials  
→ connector  
→ database health  
→ event ingestion  
→ SecurityEvent normalization  
→ detection  
→ risk scoring  
→ evidence  
→ alert  
→ API  
→ dashboard

Once that chain works, expand all required detection types.

---

# 97. REPORTING FORMAT

After every bounded implementation task, report:

## Implemented

What actually changed.

## Files changed

Relevant files only.

## Verification

Commands and tests actually executed.

## Result

- PASS
- PARTIAL
- FAIL
- BLOCKED
- NEEDS TESTING

## Existing regressions

Any regressions discovered.

## Remaining work

What is not complete.

## Next action

Exactly one concrete next engineering action.

Do not dump entire files.

Do not dump huge diffs unless specifically requested.

---

# 98. FIRST EXECUTION NOW

Begin now.

Do not begin with a large rewrite.

Perform these actions in order:

1. Inspect the project structure.
2. Read existing README/setup documentation.
3. Capture the development baseline.
4. Inspect backend architecture.
5. Inspect frontend architecture.
6. Inspect database models and migrations.
7. Inspect authentication.
8. Inspect authorization/RBAC.
9. Inspect secret/configuration handling.
10. Inspect WebSockets.
11. Inspect agents.
12. Inspect detection engine.
13. Inspect attack simulator.
14. Inspect Docker and Compose.
15. Inspect tests.
16. Run existing tests where possible.
17. Start existing services where practical.
18. Identify working features.
19. Identify partially working features.
20. Identify broken features.
21. Identify simulated/mock functionality.
22. Identify missing features.
23. Identify security vulnerabilities.
24. Identify architectural blockers.
25. Create/update `PROJECT_PROGRESS.md`.
26. Give a concise audit report.
27. Select the highest-priority bounded engineering task.
28. Implement it.
29. Test it.
30. Verify no important regression occurred.
31. Update documentation.
32. Update progress tracking.
33. Continue to the next dependency-aware task.

Prioritize:

1. Critical security defects
2. Core architecture foundations
3. Database Guardian vertical slice
4. PostgreSQL Docker validation
5. Remaining Database Guardian features
6. Agent platform
7. Detection and incidents
8. Frontend completion
9. Desktop application
10. Deployment/testing/documentation completion

---

# FINAL ENGINEERING RULE

Preserve working functionality.

Inspect before changing.

Verify assumptions.

Use the smallest safe change.

Build reusable architecture where justified.

Implement every required feature.

Prefer real end-to-end functionality over superficial breadth.

Do not fabricate telemetry.

Do not fabricate test results.

Do not confuse detection with prevention.

Do not mark incomplete work as complete.

**Build Skylos systematically until the complete required feature set is implemented, integrated, tested, documented, and verified.**
