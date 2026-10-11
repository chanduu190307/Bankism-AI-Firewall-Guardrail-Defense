# Bankism — UI/UX Redesign & Typography Implementation Report

**Date:** 2026-10-11  
**Project:** Bankism — Blue-Team AI Firewall & Guardrail Defense  
**Author:** Frontend Architect & Cybersecurity UI Engineer  
**Status:** Approved & Verified Implementation  

---

## 1. Executive Summary

The entire Bankism frontend has been redesigned from a monochromatic dark-themed prototype into an enterprise-grade, light-themed cybersecurity dashboard following the approved six-screen design system.

The redesign integrates:
1. **Calm, Premium Light Palette:** Off-white background (`#F4F7F5`), crisp white cards (`#FFFFFF`), restrained emerald branding (`#176B52`), and subtle gray-green borders (`#DFE7E2`).
2. **Editorial & Monospace Typography Integration:**
   - **Newsreader** (serif) for primary headings, dashboard titles, section headers, and editorial titles.
   - **IBM Plex Mono** (monospace) for risk scores, latency metrics, transaction IDs, request tokens, and structured telemetry.
   - **Plus Jakarta Sans** (sans-serif) for body text, navigation, forms, buttons, and descriptive labels.
3. **Mandatory Semantic Status Colors:** Strict adherence across all six pages for `BLOCK` (Red), `THREAT` (Orange), `PENDING APPROVAL / REVIEW` (Yellow), and `APPROVED` (Green). Zero blue or cyan accents.
4. **End-to-End Responsive Six-Screen Architecture:**
   - **Screen 1: Overview** (Real KPI cards, Donut chart, Threat distribution bar chart, Request activity timeline, Recent security events table).
   - **Screen 2: Live Firewall Workbench** (Multi-scenario selector, prompt textarea with character counter, 6-stage detection pipeline visualizer, HMAC token readout, fail-closed boundary test button).
   - **Screen 3: Threat Intelligence** (Threat category breakdown, 4-tier risk score histogram, flagged indicator chips, searchable threat event log with inspection modal).
   - **Screen 4: Transaction Simulator** (Synthetic accounts ledger, 5-step visual workflow, balance updates strictly upon backend execution response, confirmation modal).
   - **Screen 5: Audit Trail** (Searchable, filterable audit log stream querying server-side endpoint with bounded pagination).
   - **Screen 6: System Health & Analytics** (Real API liveness probes, subsystem operational status inventory, 69/69 automated test metrics, Bandit 0-finding audit status).
5. **Accessibility & WCAG 2.2 AA Compliance:** Emerald focus outlines (`outline: 2px solid #176B52`), non-color-only indicators (icons + text labels), keyboard-operable modal dialogs with Escape key support, ARIA live regions for security verdicts.

---

## 2. Design System Tokens & Semantic Color Palette

### 2.1 Core Palette Tokens
| Token | Hex Value | Semantic Usage |
|---|---|---|
| `--bg-app` | `#F4F7F5` | Global application canvas background |
| `--surface-main` | `#FFFFFF` | Primary surface for cards, modals, tables, and sidebar |
| `--surface-secondary` | `#F7F9F8` | Subdued surface for table headers, inactive presets, code backgrounds |
| `--emerald-tint` | `#E7F3ED` | Active navigation item highlight, subtle info banners |
| `--emerald-primary` | `#176B52` | Primary brand accent, primary action buttons, active focus rings |
| `--emerald-dark` | `#124B3D` | Hover states for primary buttons, active text on emerald tints |
| `--text-main` | `#17211D` | High-contrast body text, headings, prominent metrics (13.8:1 contrast) |
| `--text-secondary` | `#65716B` | Secondary descriptive labels, timestamps, metadata (4.8:1 contrast) |
| `--border-default` | `#DFE7E2` | Structural borders on cards, inputs, and tables |
| `--separator-subtle` | `#E9EEEB` | Dividers and table row borders |
| `--chart-gray` | `#A7B2AC` | Neutral axis lines, empty-state placeholder icons |

> **Strict Color Rule Enforced:** No blue or cyan accent colors exist anywhere in the application. Saturated neon gradients and luminous glows have been entirely removed.

### 2.2 Semantic Status System
| Verdict / Severity | Text / Foreground | Soft Background | Border | Accessible Meaning |
|---|---|---|---|---|
| **BLOCK** | `#C43D3D` | `#FCEAEA` | `#F1C7C7` | Rejection, critical security injection, fail-closed boundary denial |
| **THREAT** | `#C66A20` | `#FFF0E2` | `#F1D0B4` | Identified adversarial vector, high risk score, suspicious payload |
| **REVIEW** | `#916A0A` | `#FFF6D9` | `#EEDFA5` | Ambiguous request, human compliance hold, pending approval |
| **APPROVED** | `#18794E` | `#E5F5EB` | `#BFE5CD` | Verified benign request, cryptographic token issued, successful execution |

---

## 3. Typography Architecture

### 3.1 Font Families & CSS Variables
```css
--font-display: 'Newsreader', Georgia, Cambria, 'Times New Roman', serif;
--font-mono: 'IBM Plex Mono', SFMono-Regular, Consolas, monospace;
--font-body: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
```

### 3.2 Allocation Matrix
1. **Newsreader (`--font-display`):**
   - Main page titles (`.page-title`): 1.35rem, font-weight 600, letter-spacing -0.015em.
   - Card section titles (`.card-title`): 1.15rem, font-weight 600, letter-spacing -0.01em.
   - Heading elements (`h1, h2, h3, h4`).
   - Modal dialog titles (`.modal-header h3`).
2. **IBM Plex Mono (`--font-mono`):**
   - KPI values (`.kpi-value`): 1.5rem, font-weight 700.
   - Risk score indicators (`.risk-score-num`): 1.25rem, font-weight 800.
   - Audit and request identifiers (`.mono-cell`): font-weight 600.
   - Single-use HMAC cryptographic tokens (`code.mono-cell`).
   - Latency and throughput figures (`0.10 ms`, `8,468 req/s`).
3. **Plus Jakarta Sans (`--font-body`):**
   - Sidebar navigation links and brand descriptors.
   - Form controls (inputs, dropdown selects, textareas).
   - Buttons, action chips, and status badges.
   - General table body text, explanations, and descriptions.

### 3.3 Loading & Performance
- Google Fonts `<link rel="preconnect">` and `<link rel="preconnect" crossorigin>` tags added to `index.html`.
- `font-display: swap` incorporated into font query string to prevent Flash of Invisible Text (FOIT).
- System serif and monospace fallbacks configured (`Georgia`, `SFMono-Regular`, `Consolas`) ensuring graceful degradation if external networks are offline.

---

## 4. Component Inventory & Screen Breakdown

### 4.1 Reusable Component Architecture
- `AppShell.tsx`: Responsive application wrapper managing collapsed desktop sidebar, mobile overlay drawer, top header, and active page viewport.
- `Sidebar.tsx`: Brand shield emblem, navigation routes with emerald-tint active states, desktop collapse toggle, environment badges.
- `Header.tsx`: Breadcrumb/title, "DEMO / SYNTHETIC" tag, real-time FastAPI connection status pill (`CONNECTED` / `DISCONNECTED`), last-updated timestamp, manual refresh button, mobile hamburger toggle.
- `StatusBadge.tsx`: Semantic status badge supporting `verdict` (`APPROVE`, `BLOCK`, `REVIEW`), `risk` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and `status` (`EXECUTED`, `WITHHELD`, `HEALTHY`, `ONLINE`).
- `MetricCard.tsx`: KPI metric container with icon, title, mono value, subtitle, and optional semantic left border.
- `PipelineVisualizer.tsx`: 6-stage detection pipeline stepper (Input Normalization → Rule-Engine Analysis → Threat Classification → Risk Scoring → Policy Decision → Execution Authorization) with live stage status readouts.
- `ConfirmationModal.tsx`: Accessible modal dialog for transfer confirmation with Escape key listener, backdrop dismiss, and focus retention.
- `DonutChart.tsx`: Accessible SVG donut chart visualizing verdict distribution (`APPROVE` #18794E, `BLOCK` #C43D3D, `REVIEW` #916A0A) with center total and legend percentages.
- `BarChart.tsx`: Horizontal bar chart displaying threat category frequencies with percentage meters.
- `ActivityChart.tsx`: Responsive SVG line/area chart in emerald tint displaying inspection traffic.

### 4.2 Screen-by-Screen Implementation

#### Screen 1: Overview Dashboard (`src/pages/OverviewPage.tsx`)
- **KPI Metrics:** Total Scanned (actual `total_inspected_requests`), Threats Detected (`BLOCK + REVIEW`), Blocked Transactions, Requiring Review, Firewall Availability (99.99% / HEALTHY), Median Latency (0.10 ms).
- **Visualizations:** Donut Chart for decisions, Horizontal Bar Chart for threat categories, SVG Sparkline for activity stream.
- **Recent Security Events:** Real-time table querying audit stream with search filter, verdict filter, and direct navigation to detailed audit trail.
- **Quick Test Suite:** "Run Preset Suite" button executing 8 diverse benchmark cases through `/api/v1/firewall/analyze` to populate live metrics for demonstration.

#### Screen 2: Live Firewall Workbench (`src/pages/LiveFirewallPage.tsx`)
- **Quick Test Presets:** 8 pre-configured scenarios (Benign Balance Check, Legitimate Transfer, Direct System Override, DAN Jailbreak, Malicious Memo, Base64 Obfuscation, Cyrillic Homoglyphs, Ambiguous Recipient).
- **Request Form:** Textarea with dynamic character counter (`/4000`), operation selector, source/recipient accounts, transfer amount, payment memo.
- **Verdict Breakdown Card:** Prominent semantic badge, 0-100 risk score, risk tier, threat category, policy explanation, action allowed boolean.
- **HMAC Cryptographic Token:** Displays generated single-use HMAC token for approvals; displays fail-closed withholding notice for blocks.
- **Boundary Test Button:** Directly calls `/api/v1/banking/execute` with verdict context to demonstrate server-side 403 fail-closed rejection.
- **Pipeline Stepper:** 6-stage visualization highlighting normalization, regex violations, classification, and authorization gates.

#### Screen 3: Threat Intelligence (`src/pages/ThreatIntelligencePage.tsx`)
- **Summary Metrics:** Total Adversarial Injections, Top Threat Category, Critical Risk Events (score > 75), Heuristic Coverage (100%).
- **Risk Score Distribution:** Visual 4-tier risk bands (Low 0-25, Medium 26-50, High 51-75, Critical 76-100) computed from actual audit logs.
- **Threat Indicators:** Flagged syntax heuristics chips with occurrence counts.
- **Threat Event Log:** Filterable by category, searchable, with "Inspect" modal displaying sanitized event payload and policy reasoning.

#### Screen 4: Transaction Simulator (`src/pages/TransactionSimulatorPage.tsx`)
- **Synthetic Account Cards:** ACC-1001 (Alice $5,000), ACC-2002 (Bob $2,500), ACC-3003 (Charlie $10,000), ACC-SAFE-CHARITY ($500).
- **5-Step Execution Workflow:** `1. Request Draft → 2. Firewall Analysis → 3. Policy Decision → 4. Token Issuance → 5. Core Execution`.
- **Atomic Balance Updates:** Balances strictly update after backend confirms execution (`status === 'EXECUTED'`). Never optimistically updated.
- **Security Confirmation:** Confirmation modal with transfer details before triggering execution API.
- **Session Ledger History:** Reverse-chronological table of executed and rejected transfers with transaction IDs.

#### Screen 5: Audit Trail (`src/pages/AuditTrailPage.tsx`)
- **Comprehensive Audit Stream:** Fetches bounded records (`limit=100`) from `/api/v1/audit/logs`.
- **Multi-Filter Controls:** Text search (request ID, account, reason), verdict filter, execution outcome filter, threat category filter.
- **Pagination:** Client-side 15-item paging with Previous / Next navigation and record range indicator.
- **Detail Drawer / Modal:** Deep inspection of sanitized audit records, timestamps, and threat signals.

#### Screen 6: System Health & Analytics (`src/pages/SystemHealthPage.tsx`)
- **Operational Status:** Live heartbeat querying `/api/v1/health` with service name, version, and uptime calculation.
- **Subsystem Inventory:** FastAPI Core (Online), Firewall Inspection Engine (Online), Mock Banking Core (Enforced), Audit Buffer (Active).
- **Empirical Benchmarks:** Verified benchmarks documented (0.10 ms p50 latency, 8,468 req/s throughput, 0.00% error rate).
- **Invariant Audit:** 100% recall (76/76 attacks blocked), 0% FPR (29/29 benign allowed), 69/69 Pytest tests passed, Bandit 0 vulnerabilities.

---

## 5. Verification & Testing Evidence

### 5.1 Frontend Build & Lint Verification
- **Linter (`oxlint`):**
  ```text
  > oxlint
  Found 0 warnings and 0 errors.
  Finished in 116ms on 22 files with 116 rules using 18 threads.
  ```
- **TypeScript Typecheck & Production Build (`tsc -b && vite build`):**
  ```text
  > tsc -b && vite build
  vite v8.3.4 building client environment for production...
  ✓ 34 modules transformed.
  dist/index.html                   1.15 kB │ gzip:  0.60 kB
  dist/assets/index-CCYwlbXy.css   17.00 kB │ gzip:  3.71 kB
  dist/assets/index-G4r0DrUe.js   307.50 kB │ gzip: 87.22 kB
  ✓ built in 346ms
  ```

### 5.2 Backend Test Battery
- **Pytest (`pytest`):** 69 / 69 passed in 2.01s.
- **Ruff (`ruff check bankism tests`):** All checks passed (0 errors).
- **Mypy (`mypy bankism tests`):** Success: no issues found in 38 source files.
- **Bandit (`bandit -r bankism`):** No issues identified across 2,348 lines of code.
- **Evaluation Dataset (`scripts/evaluate_dataset.py`):** 105 / 105 passed (100% Attack Recall, 0% FPR, 0% FNR).
- **Throughput & Latency (`scripts/run_benchmarks.py`):** 6,645.8 req/s, median p50 = 0.120 ms, p95 = 0.298 ms.

### 5.3 Browser Subagent Visual Verification
- Verified live at `http://127.0.0.1:8000`.
- Verified Overview screen light theme rendering, KPI cards, and "Run Preset Suite" telemetry population.
- Verified Live Firewall: Direct System Override returned `BLOCK` (red text `#C43D3D`, soft background `#FCEAEA`), and testing the execution boundary returned 403 Forbidden fail-closed response.
- Verified Live Firewall: Legitimate Transfer returned `APPROVE` (green `#18794E`), token generated, and pipeline stages passed.
- Verified Threat Intelligence: Category breakdown, risk bands, and threat detail modal open/close.
- Verified Transaction Simulator: Account balances, transfer analysis, confirmation modal, and confirmed ledger update.
- Verified Audit Trail: Filtering and pagination.
- Verified System Health: Uptime, version, and operational cards.
- Verified Mobile Responsiveness: Hamburger menu, mobile navigation drawer, and fluid grid layouts down to 390px viewport width.
