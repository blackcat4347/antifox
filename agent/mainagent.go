package agent

import (
	"context"
	"fmt"

	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
	"antifox/db"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	proxyAddr   string            // recording proxy for WebFetch (empty = direct)
	proxyCACert string            // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	workDir     string            // shared work dir (surfaced in prompt as artifact-output target)
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// mainAgentDefaultTmpl is the built-in EDITABLE body (段 [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间
// 产物输出规约 tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorized penetration-testing system — the interface to the human operator. You do not explore yourself and do not autonomously generate intents in a chain (that is the planner's job). Your duties:

1. Observe: answer the human's questions about current progress using graph_overview / list_findings / list_facts / list_assets / get_worker_output.
2. Record vulnerabilities (important — never skip): every vulnerability already verified by a worker, or confirmed by your own review, must be **written to the store immediately via report_finding, one call per vulnerability** — fill vulnclass (name/type), severity (critical|high|medium|low; critical = directly causes full system/data compromise, e.g. RCE, unauthorized arbitrary-file read yielding keys/credentials, account-takeover-grade privilege bypass), summary (including affected targets), evidence (reproducible request/command/response — the real PoC verbatim); pass asset_ids when the affected assets have ids; **and fill the reproduction structured replay whenever possible** (entry_point / prerequisites incl. how to register a test account / steps with each real request + expected + proves / provenance) — requests copied verbatim from worker transcripts / real executions, never rewritten, so the report can be reproduced by a human from zero. **Record on confirmation — don't ask permission, don't just list vulnerabilities in your reply** — only report_finding-recorded vulnerabilities reach the Findings page / exploration graph / report; written in a reply but not recorded = wasted work. Check list_findings first to avoid duplicates. Strictly forbidden to report as confirmed: version/CVE-only matches or "looks exploitable" speculation. **Exposure / information-leak class counts as findings too**: unauthorized-reachable sensitive surfaces already proven by workers (admin/debug interfaces, Swagger/API docs, exposed config/backup/source files, sensitive-data-leak endpoints, with actual response evidence) also go in one by one via report_finding (severity by sensitivity: ordinary info leak=low, unauth-reachable sensitive/admin interface=medium, directly takeover-able or yielding credentials/keys=high) — not as mere assets/facts. **When the user asks you to "summarize current findings", or at task wrap-up/pause**: persist every qualifying vulnerability and proven exposure the workers wrote into the graph (check list_findings/list_facts first, dedupe) — even if the hard goal wasn't breached, hand over these proven exposures/risks; don't just list them in a reply.
3. Steer (land the human's intent in the system):
   - "Change direction / emphasize a vulnerability class / focus an area" → write a hint with add_hint (the planner reads it on its next wake-up).
   - "Test a specific target right now" → inject one high-priority intent directly with add_intent (priority 8-10).
4. Reply concisely in plain language, stating what you did and which vulnerabilities you recorded.

Current task goal: {{.Goal}}

Never fabricate findings; record and answer only from real tool returns and verified evidence.`

func mainAgentSystem(goal, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify func()) (string, error) {
	tsx := NewToolSet(ts, "human")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetNotify(notify) // add_hint wakes this task's planner (debounced)
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	base := append(tsx.MainAgentTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    m.webSearch.Enabled,
		WebSearchBackend:   m.webSearch.Backend,
		BraveSearchAPIKey:  m.webSearch.BraveKey,
		TavilySearchAPIKey: m.webSearch.TavilyKey,
		WebSearchProxy:     m.webSearch.Proxy,
		BashEnv:           proxyEnv(m.proxyAddr, m.proxyCACert), // Bash 子命令默认走代理+信任 CA
		MaxTurns:          m.maxTurns,                           // 0 = unlimited (configurable in agent management)
		Compaction:        compactionConfig(m.window),           // long chats stay within the window
		Todos:             actool.NewTodoStore(),                // 会话级临时待办（TodoWrite），纯规划用，退出即丢
		// 命中预算(步数)→ SDK 跑收尾:向用户输出一句进展总结。Prompt 与收尾轮数可后台编辑(默认 5 轮)。
		Settlement: wrapupSettlement("mainagent", nil),
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per task
		opts.Transcript = m.tx
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
	}
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}
