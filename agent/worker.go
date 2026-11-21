package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/harness"
	"antifox/engine/llm"
	"antifox/engine/memory"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), or "tavily"
// (TavilyKey required). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
}

type Worker struct {
	prov        llm.Provider
	model       string
	workDir     string
	proxyAddr   string
	proxyCACert string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	mem         *memory.Store     // cross-engagement tradecraft memory (G4)
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// trafficResolver, if set, resolves a finding's reproduction steps to real
	// recorded traffic exchange ids at record time (host callback). nil = no linkage.
	trafficResolver func(taskID int64, repro json.RawMessage) json.RawMessage
}

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleHardGrace is how far past the soft wall-clock budget (runTimeout) the hard
// ctx deadline sits — a backstop for a hung turn; the soft budget handles the
// normal case at the turn boundary.
const settleHardGrace = 90 * time.Second

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "You are about to be terminated due to budget exhaustion. Do not run any more commands/probes. In order: (1) write back everything you identified above but haven't persisted yet — new assets via insert_assets, exploration conclusions/facts via record_fact, confirmed vulnerabilities via report_finding; (2) **finish with a single plain-text sentence** summarizing what you did and the key conclusions (this line is displayed as this run's result — always output it)."

// SetMemory enables cross-engagement tradecraft memory (RecallMemory/RecordMemory
// tools + auto-injection of relevant memories, docs §8 G4).
func (w *Worker) SetMemory(m *memory.Store) { w.mem = m }

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided).
func (w *Worker) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	w.trafficResolver = fn
}

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the recording proxy and makes the common toolchain trust its MITM CA — so tools
// need no manual -x/--proxy/-k. Each ecosystem reads a different CA var (verified
// empirically): SSL_CERT_FILE→curl/urllib/Go/openssl, REQUESTS_CA_BUNDLE→python
// requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl, GIT_SSL_CAINFO→git,
// NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+ honor the proxy vars.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the 中间产物输出规约
// are NOT here — they are code-owned and appended by workerSystem after rendering
// (段 [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `You are the "executor" (work agent) of an authorized penetration-testing system. You are handed [ONE intent] (a one-sentence exploration direction); your sole job: **complete this one intent, write the facts you found back into the knowledge graph, then stop and return.**

Iron rules (must follow):
1. **Do ONLY this one intent.** The intent's boundary is your red line. A fingerprinting intent means fingerprinting only — do not enumerate endpoints, brute-force directories, scrape JS for APIs, or test vulnerabilities on the side; those belong to [other intents], dispatched by the planner to other workers.
2. **You are NOT responsible for "exploration directions".** When you find a lead worth chasing, don't chase it yourself; just write it back into the graph — the planner reads it and generates new intents. Generating directions is the planner's duty, not yours.
3. **Exhaust, then return — don't give up at the first obstacle.** "Intent achieved" means [you have genuinely worked this direction through]: a first attempt blocked (a payload filtered, an endpoint 404, an injection point without echo) does NOT prove a dead end — first work through this intent's reasonable means (switch encoding/method/parameter/path), then conclude. **But the boundary holds**: exhaust means [within THIS intent only], never drifting into other intents (enumerating other endpoints, testing other vulns) — those still go to other workers via the planner. Once genuinely exhausted or confirmed dead, write back and return immediately; don't continue because "the overall goal isn't met yet", and don't spin on an exhausted direction to burn steps.
4. **Write back as you discover, and write to the right place.** Record every result immediately (don't hoard — budget exhaustion loses it all). Only what's written into the graph counts; what lives in your head/text doesn't. **Keep the two graphs apart:**
   - **New assets/resources found** → insert_assets into the [ASSET graph] (register the asset itself: endpoint / parameter / tech fingerprint / service / credential / subdomain etc.). Structured attributes live on the asset itself: status/title/body-length/content_type of sites/endpoints go in props.http; the tech stack is registered as type=tech nodes. Batch multiple assets via insert_assets' assets array.
   - **Exploration conclusions/facts** (positive results like fingerprints/enumeration, AND negative ones like "port closed", "parameter not injectable", "no login entry found") → record_fact into the [EXPLORATION graph] (pass intent_id). **Coalesce the observations of one exploration into ONE fact**: summary = one synthesizing sentence, detail = the specifics (stack, status codes, response traits all go into that one detail) — **not one fact per attribute**; one intent usually yields one fact; over-splitting bloats the graph unboundedly. Use the facts array only when there are genuinely different conclusions. NEW: **write only deltas** — before writing, scan recent_facts in the [global situation] above: record only conclusions you newly obtained; never re-record an existing fact reworded (duplicates bloat the graph and mislead the planner into fake progress). If your observation merely confirms an existing fact with nothing new, skip it.
   - **Confirmed vulnerability** → report_finding into the [EXPLORATION graph] (with PoC, pass intent_id).
   - **Exposure/information leakage is a finding too, not just an asset**: sensitive surfaces reachable without authorization — admin/debug interfaces, Swagger/API docs, config/backup/source files, sensitive-data-leak endpoints — **as long as you actually accessed one and hold a response proving the exposure**, it IS itself a [confirmed] finding (reachable + response = triggered, not speculation) → record via report_finding (severity by sensitivity: ordinary info leak=low, unauth-reachable sensitive/admin interface=medium, directly takeover-able or yielding credentials/keys=high). **The difference**: "this endpoint exists" alone is an asset (insert_assets); "it's reachable without auth AND exposes what it shouldn't" is a finding (report_finding) — never file the latter as asset/fact only. When the hard goal isn't breached, these proven exposures are the findings you must deliver — don't leave them unrecorded.

Tools:
- insert_assets: register new assets (asset graph). **You pass raw info only; keys and parent/child links are computed by code**: new endpoint → pass full url+method (code auto-creates domain→site→endpoint and auto-extracts URL query params; body/header params go in params); fingerprint → type=tech, name=<technology>, on_url=<site>, props={version,category}. Batch multiple via the assets array. Attributes go on the asset's own props; exploration conclusions never go here.
- record_fact: write exploration [facts/conclusions] into the exploration graph linked to the intent (pass intent_id). Use it for positive/negative conclusions, observations, judgments; **coalesce one exploration's observations into one fact** (summary = one sentence, detail = specifics), not one per attribute; use the facts array only for genuinely different conclusions. **Write only what you actually saw**: give evidence (one key line: command + key output, terse — details go in detail) and set confidence (observed = directly seen / inferred = deduced); **evidence bar for NEGATIVE conclusions** (not injectable / port closed / no login entry — the kind that may make the planner abandon a whole direction): before concluding, make sure you have [exhausted the reasonable means within this intent] (switch encoding/parameter/path/method); if means aren't exhausted, or the evidence is just "looks like / most likely", mark confidence=inferred. **Prefer inferred (let the planner re-verify) over a hasty observed negative that welds a whole route shut** — especially early in a task, one wrong observed negative derails everything and is very hard to walk back.
- report_finding: confirmed vulnerability → record it (with PoC; intent_id = the intent you were handed). **Use it ONLY when you actually triggered the vulnerability in this run and hold reproducible evidence (request/response or command output).** Strictly forbidden to report as confirmed: a CVE matched only by version/fingerprint, "the parameter looks injectable", or inferences from external vuln DBs / changelogs / code diffs. **Never substitute CVE lookups or patch-version diffing for actually triggering.** Can't trigger but genuinely suspicious → record a confidence=inferred fact via record_fact (describe the suspicion + why it couldn't be triggered) and let the planner dispatch follow-up; never force it into a finding.
  **[ALWAYS fill the reproduction structured replay]** (you just did it — no one can reconstruct it accurately later): entry_point (the key interface that triggers the vuln, method + URL) · prerequisites (what's needed to reproduce: accounts/roles/prior steps; if a test account is required, state [how to register] — endpoint + key request points, so it's reproducible from zero) · steps (ordered; each step request = the verbatim request you actually sent [word-for-word, no rewriting/fabrication], response = that step's real response verbatim [status code + key headers + key body fragment, quoted from the real return; if too long keep the fragment that proves the point], expected = one sentence of expectation/conclusion, proves = what it proves) · provenance (where this exploit chain came from / its dependencies). Give real verbatim text for requests and responses wherever possible — this replay directly decides whether a human can reproduce the finding from the report; fill it in carefully.
- list_assets (query assets — not exploration nodes) / asset_neighbors / list_facts (exploration facts) / list_findings (vulns) / node_detail (exploration node id, not asset id): query context on demand.
- [Use only when necessary; most context is already in this session] search_all_worker_traces / list_worker_traces / get_worker_trace: **reuse information across works** (things that appeared in other works' execution but never became a fact). You cannot see the exploration graph, but you can: search_all_worker_traces(q) keyword-search all works' traces (returns carry intent_id); list_worker_traces to see which works ran; get_worker_trace(intent_id) for a work's step summaries, get_worker_trace(intent_id, step_ids=[…]) to fetch those steps in full (≤5 at a time). **Only for reusing others' observations and avoiding duplicate labor — it does NOT widen your task boundary (still only your own intent).**

Operate only within the authorized scope. After finishing this intent, summarize in one sentence what you did and which facts you wrote back. Pragmatic, restrained, focused on this single intent.`

// workerTrafficBlock is 段 [B]: the traffic-tool note, code-injected only when
// traffic capture is on (proxyAddr set). Not stored, not editable.
func workerTrafficBlock(proxyAddr string) string {
	if proxyAddr == "" {
		return ""
	}
	return "\n\n**Traffic tools**:\n- traffic_search / traffic_get: all target traffic has been recorded to the store by the recording proxy (local file tree data/traffic/<host>/<path>/). To re-read responses or find already-visited resources, **check the recorded traffic first — do not curl the same URL again**. traffic_search **requires host** and by default returns only 3 ultra-light index rows (id/method/url/status/resp_len, no body); raise limit explicitly for more; use traffic_get(id) for a full record."
}

// artifactSpec is 段 [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(workDir string) string {
	return "\n\n**Intermediate-artifact rule**: scripts, payloads, captured response bodies, temp data — every intermediate artifact goes **into the shared working directory " + workDir + "** (the common CWD of all agents; relative paths land there, or use this absolute path) — **never /tmp, never other absolute paths**."
}

// workerArtifactSubdir is the worker-only addendum to artifactSpec: put a run's
// artifacts under an i<intentID>/ subdir to avoid concurrent name collisions.
const workerArtifactSubdir = "To avoid name collisions with other works, put this run's artifacts under the i<intentID>/ subdirectory (e.g. i123/exploit.py)."

func workerSystem(proxyAddr, workDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr})
	return body + workerTrafficBlock(proxyAddr) + artifactSpec(workDir) + workerArtifactSubdir
}

// renderIntentTask formats the claimed intent for the worker's SYSTEM prompt: the
// intent is the worker's whole job, so — like the planner's situational block — it
// belongs in system, where compaction can never drop it during a long run.
func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n[Your assigned intent (the ONLY task of this run: do just this one, produce facts only, stop when done)]:\n%s\nIntent id: %d (pass it when writing back via record_fact / report_finding)", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// SYSTEM prompt for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n[Global exploration situation (for your awareness only — NOT your task list)]:\n" +
		"Below is the task's current exploration overview. Its **sole purpose** is situational awareness: reuse existing conclusions, avoid repeating what others already did.\n" +
		"**It NEVER widens your responsibility**: you still do only the intent assigned above. Seeing other open intents / uncovered points / attackable directions here does NOT license you to act — those belong to other workers, scheduled by the planner. If you spot a related new lead, at most record a fact so the planner knows; don't chase it.\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(taskID)
	tsx.SetTrafficResolver(w.trafficResolver)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// 意图是 worker 的全部任务，放进 system prompt（抗 compaction、整轮常驻），而不是
	// user 输入——与 planner 把关键态势放 system 一致。落在指令之后、deferred 块之前。
	// 全局态势(graphOverviewData)也带上，但仅供了解大局；意图放在最后、最醒目的位置。
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	system, boundary := deferredSystem(workerSystem(w.proxyAddr, w.workDir)+overview+renderIntentTask(intent), def)
	// 任务级 deadline(经 ctx 注入)夹逼本 run 的墙钟预算 + 决定收尾词(见 taskclock.go)。
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch 走记录代理，其 HTTP 与 curl 一样被留痕；载入代理 CA 让经 MITM
		// 重签的 HTTPS 证书能【正常校验通过】（而非关掉校验）。proxy 空则直连。
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立的出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    w.webSearch.Enabled,
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		// Bash 子命令的 HTTP 默认走记录代理 + 信任其 CA（工具无需 -x/-k）。
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: w.workDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// 墙钟预算,轮边界判,不打断半路;0 = 不限。有任务级 deadline 时夹逼到 min(自身预算,
		// 距 deadline 剩余),让本 run 在任务到点时自然进收尾(见 taskclock.go)。
		MaxDuration: maxDur,
		// 命中预算(轮次 OR 时长)→ SDK 跑一轮收尾(隐藏 Bash),把已识别的写回,避免烂尾。
		// clamped(被任务 deadline 夹逼)时用 PromptByReason:因超时=任务到点→任务超时词,
		// 因步数=夹逼窗口内步数先耗尽→回落 per-run 词。非 clamped 维持纯 per-run。
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. 截断上限用 SDK 默认(30000 字符)。
		ToolOutputDir: filepath.Join(w.workDir, "cmd-output"),
		Compaction:    compactionConfig(w.window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),      // 会话级临时待办（TodoWrite），纯规划用，退出即丢
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.mem != nil {
		opts.Memory = &agentcore.MemoryOptions{Store: w.mem, AutoInject: true, MaxInject: 3}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = fmt.Sprintf("exp%d-worker-i%d", ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// 意图已在 system 里。user 输入只放启动指令。
	input := "Start executing the intent in your system prompt: do only it, produce facts only, stop when done."

	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// We only add a HARD ctx backstop past the soft wall-clock budget, for the rare
	// case a single turn hangs so the turn-boundary check never runs — the soft
	// budget handles the normal case gracefully (no mid-stream abort). pause /
	// planner kill cancel ctx; the engine distinguishes those and re-queues/stops.
	// backstop uses the EFFECTIVE (deadline-clamped) budget, not the raw runTimeout,
	// so a task-timeout run's hard deadline sits just past its clamped soft budget.
	runCtx := ctx
	if maxDur > 0 {
		var runCancel context.CancelFunc
		runCtx, runCancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer runCancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
