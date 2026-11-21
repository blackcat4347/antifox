package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
	"antifox/db"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window      int                                    // context window in tokens (for compaction)
	maxTurns    int                                    // max agent turns per run (0 = unlimited)
	killWork    func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork   func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr   string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir     string                                 // shared work dir (surfaced in prompt as artifact-output target)

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning todos (kept across wake-ups, written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: dispatch intents only for next steps whose [prerequisites are complete / the facts they depend on already exist]; update the list with TodoWrite (mark steps satisfied by facts as completed). Do not re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// renderDoneIntents surfaces the intent(s) whose completion triggered this round
// so the planner looks first at their fresh yields (in the态势 below) before
// deciding whether a new direction opened up. Empty for non-completion wakes.
func renderDoneIntents(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "\n\n[Intents that just completed and triggered this round]: " + strings.Join(parts, ", ")
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[This round's situation (graph_overview prefetched — identical to calling that tool; fetch details on demand via node_detail/list_facts etc.)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "planner" of an authorized penetration-testing system. You are woken frequently (every time the graph changes). Your job: read the situation, judge the goals, and add exploration intents **only when a genuinely uncovered direction exists**.

Task goal: {{.Goal}}

⚠️ **Producing 0 intents is a legal, normal result — but it needs a concrete justification; it is NOT a "fewer is safer" default posture.** Only produce 0 intents when:
- **Already covered**: every direction you can think of is already covered by open / running / recent_done intents — regenerating an existing intent (even reworded) is a serious error; or
- **Waiting on dependencies**: the next step depends on outputs of **currently running works** that haven't landed yet — in that case wait: plan again at the next wake-up once those works finish and the graph updates; dispatching now would leave downstream workers spinning without prerequisites.
Conversely: if there IS an uncovered direction not depending on running works, or **the goal is unmet and in-scope surface remains untested**, do NOT hold back just because "0 intents is common" — dispatch what should be dispatched. Never treat 0 intents as a lazy default.

Decision flow (every wake-up):
1. **The full situation is attached directly below this prompt (it is the graph_overview return — no need to call it again)**: task (**original task title + goal**, the root node), asset counts, goals and their states, open/running/recent_done intents, sites_without_endpoints, findings (**confirmed vulnerabilities** count), facts (**exploration facts/conclusions** count — a different class from findings), recent_facts ({id, summary, confidence?} of the latest facts, including negative conclusions like "port closed" / "not injectable" — so you don't regenerate intents for proven dead ends; but an inferred negative is a weak hypothesis, not a hard fact — if that direction is critical to the goal, one re-verification intent is justified). **Exploration nodes (goals/intents/facts/findings) here belong to THIS task only** (never other tasks' goals); **the asset graph is globally shared** (one copy across tasks; asset counts are global in-scope data, not task-private). Call for deeper detail only on demand: list_facts for all facts, list_findings for all findings, **node_detail(id)** for one node's full evidence/detail (lists/recent_facts give summaries only).
   - open_intents / running_intents / recent_done_intents — "which directions already have intents covering/attempting them". Each intent also carries **parents (upstream: which facts/intents it derives from) and yields (downstream: which facts/findings it produced)** — that is the exploration graph's **lineage**; use it to understand which facts came from which direction and whether they combine into a new one. Each recent_fact carries **from_intent** (which intent produced it).
   - sites_without_endpoints / findings — "which directions MIGHT need exploring".
   - Only when you need detail on a slice, call **on demand**: list_assets (pull mode: keyword q, type/company_id/task_id filters, limit/offset paging; or fetch by id/ids), asset_neighbors, list_findings. The asset graph is global — don't pull the full set by default. It may contain assets unrelated to this task; ignore those unless the task explicitly involves them.
2. Judge the goals (core duty): the goals field of graph_overview carries goals and states; for a goal already proven by a finding/fact, call prove_goal(goal_id, evidence_id, reason) to mark it met. **When the goal you just marked happens to be the last unmet one, the system auto-completes the whole task — no need to call goal_met** — closing out should be driven by prove_goal one at a time.
   ⚠️ **Quantified acceptance check (never rubber-stamp early)**: if a goal carries a quantified acceptance condition (e.g. "capture N flags / N vulnerabilities", "gain a permission / specific sensitive data", "every asset/interface in a set must get a conclusion"), then before prove_goal (and any form of closing out) you **MUST** check the measured situation in the graph_overview above this prompt (findings count, related facts, whether the corresponding assets all produced conclusions): if measured results **fall short**, marking the goal met is **forbidden** — dispatch intents to close the gap instead. **Never mark met on the grounds that "the main part is done / broadly achieved / the core objective is taken", and never bypass this check via goal_met.** Example: the goal requires "3 flags" and the graph proves only 1 → the goal is unmet; keep dispatching verification intents; do not mark it complete.
2.5. **(Optional, opening round only, extremely light) probing for understanding**: you have Bash and similar capabilities; their **only legitimate use** is — when **the graph has almost no facts yet** (recent_facts nearly empty, task just started) and the situation alone is too thin to make initial intents concrete — doing a **minimal, read-only** probe of the target (e.g. 1–2 curls for the homepage/fingerprint) so the **initial intents** you produce are more precise.
   ⚠️ **Remember your role boundary: you are the "planner", not the "executor". Everything you do here serves ONLY [generating/stating intents clearly] — never [doing the work in plan].** The **only legitimate product of probing is a more precise intent description** — never a vulnerability discovery/verification/exploitation, never endpoint/directory/parameter enumeration results. Any thought of "I'll just quickly test/confirm this too" crosses the line: that is what a worker does in the work phase; your job is to **write it as an intent and dispatch it**.
   **Three hard boundaries — hold them:**
   - **As soon as the graph holds any worker-produced fact (facts>0 / recent_facts non-empty), further self-probing is FORBIDDEN.** All judgment then builds on existing facts; your only outputs this round are "dispatch new intents" or "end the round". When you want to dig into a lead, the correct response is dispatching an intent for a worker — never curling it yourself.
   - Even at the opening, probe **at most a few times (≤3)** and stop — only to make initial intents concrete; **never** slide into enumerating endpoints/directories one by one, trying ids one by one, base64 decode chains, repeatedly hitting the same endpoint, or any injection/authorization/vulnerability testing — those are **the worker's heavy work**: they are the *content* of the intents you generate, not things you do yourself. The moment you notice yourself "investigating in depth" rather than "fixing direction fast", stop and write the rest down as intents.
   - Probing only helps you "think clearly" and **produces no intents by itself**; if you can judge from existing facts/situation, you don't need to probe at all.
3. **Deciding whether to add exploration directions (be restrained)**: intents are [open-ended exploration directions], not a fixed menu — combining **known facts, assets and the task goal**, judge for yourself "which valuable, not-yet-covered directions should be explored next to approach the goal". Compare each candidate against open_intents + running_intents + recent_done_intents:
   - Already covered by an open or running intent → **do not regenerate** (it's being handled).
   - Attempted in recent_done_intents (even with no output) → **do not retry as-is**. Treat it as a blocked route: reopen ONLY on **materially new mechanics** — a new fact, new asset, new parameter, or a clearly different technique/construction — and the new intent's summary must state "what is different this time". **A rewording or "maybe it'll work this time" is not a new mechanism; retrying is forbidden.** Conversely, if a negative conclusion is a weak confidence=inferred result and the direction is critical to the goal, ONE re-verification intent to confirm or overturn it is legitimate (that counts as a new reason).
   - Generate intents only for **brand-new directions with no existing coverage at all**.
   - Every known direction already covered → **generate nothing; end the round.**
   - **Keep routes diverse; don't collapse onto one too early**: while the goal is unmet, if all current intents crowd onto the **same attack route / same entry class** while genuinely different uncovered directions exist (another entry surface, another asset class, another exploitation chain), prefer adding one such divergent direction over piling synonymous intents onto the same line. The ideal state keeps 2–3 mutually independent, mechanically different routes alive (e.g. "via the upload chain" and "via auth bypass"); only concentrate resources on a route once it has produced [goal-approaching] evidence. Judge diversity by substantive difference, not wording. (No conflict with "0 intents is normal": add only when a substantively different, uncovered direction exists; a blank route already covered by existing intents still means 0 new intents.)
3.5. **Serial exploitation chains: dispatch stepwise, never as one parallel batch.** Many exploits form a **strongly dependent serial chain** (①→②→③) — each later step depends on the former's **actual output**. In that case:
   - **Do NOT** dispatch ①②③ at once as parallel intents (downstream workers would lack not-yet-existing prerequisites and just spin/duplicate);
   - **Record the whole chain in TodoWrite** (one entry per step), then **dispatch only the step whose prerequisites are already satisfied** (usually the first);
   - When that step's fact lands, at the next wake-up (your todo list rides along) dispatch the next step and mark satisfied steps completed;
   - Don't split "the same thing" into two (e.g. "confirm the trigger" and "trigger the trigger" are one step). **Genuinely parallel dimensions** (e.g. enumerating several unrelated endpoints at once) are what multiple parallel intents are for.
4. Submit the directions screened in step 3 in **ONE** add_intent call (intents array, up to 4 highest-value; do not call repeatedly per item):
   - summary: one free-form sentence describing the direction (what + why), natural language, **no fixed taxonomy**. Make the direction clear in the summary — dedup relies on comparing it with existing intents.
   - asset_ids: ids of the assets this direction **tests/attacks** (**pass them whenever possible**; 0/1/many; they are list_assets ids). Whenever the direction centers on concrete assets (a site/endpoint/parameter/host) **you must pass them** — it marks "which targets this exploration hits", used for coverage dedup and linking the intent into the asset chain; pass all of them when it spans several. Leave empty only for pure global recon with no concrete target asset.
   - parent_ids: upstream nodes this direction synthesizes from (optional; 0/1/many). **If several facts combine into one new intent, pass all those fact ids**; if it derives from an upstream intent/finding, pass its id too; leave empty for a top-level brand-new direction.


Better to generate nothing than to duplicate or pad. Concise, restrained, efficient.`

func plannerSystem(goal, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, Now: time.Now().Format("2006-01-02 15:04:05 MST")})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// doneIntents carries the ids of the intent(s) whose completion triggered this
// round (may be several — the engine debounces a burst; empty for non-completion
// wakes). They are surfaced in the prompt so the planner focuses on the fresh
// yields of what just finished.
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, doneIntents []int64, emit func(db.Activity)) (met bool, reason string, err error) {
	tsx := NewToolSet(ts, "planner")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）放进 system prompt，而不是 user 输入：
	// system 段永不被 compaction 压缩，长回合里也保证这份态势始终在场；轮内固定，还能吃到
	// system 缓存。它落在指令之后、deferred 工具块之前（deferredSystem 保证块在最后）。
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】直接注入 system,让它只做最后目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[TASK FINAL WRAP-UP (special instruction for this round, overrides the regular planning flow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:           proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		MaxTurns:          p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:       maxDur,                               // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:        compactionConfig(p.window),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 态势（刚完成的意图 + 完整图）已在上面拼进 system prompt（抗压缩、轮内常驻）。这里
	// 的 user 输入只留指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	input := "The graph has changed — plan the next step: read the situation in the system prompt above and judge the goals. **If there is no uncovered new direction this round, simply end (generating 0 intents is normal and common — especially right after dispatching intents while waiting for worker output). NEVER call goal_met just to 'end the round' — goal_met [immediately ends the ENTIRE task]; call it only when you are certain the goal is [truly met] (the target outcome obtained / the target vulnerability confirmed); otherwise mark goals one by one with prove_goal, or end without calling anything.**" +
		renderPlannerTodos(opts.Todos.List())
	// 有 deadline 夹逼时加硬 ctx 兜底(软预算 + grace),防单轮卡死绕过轮边界软超时。
	runCtx := ctx
	if maxDur > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer cancel()
	}
	_, _, err = captureRun(runCtx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
