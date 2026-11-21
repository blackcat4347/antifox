package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	acperm "antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/db"
	"antifox/knowledge"
)

// compactIntents distills intents to {id, summary, state, asset_ids, parents,
// yields} so the planner sees both the direction and its LINEAGE — parents (the
// upstream nodes it derived from: facts/intents/findings) and yields (the facts/
// findings it produced) — without pulling full payloads. parentsOf/yieldsOf are
// built from the exploration edges in graph_overview.
func compactIntents(ns []*db.Node, parentsOf, yieldsOf map[int64][]int64) []map[string]any {
	out := make([]map[string]any, 0, len(ns))
	for _, n := range ns {
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		m := map[string]any{"id": n.ID, "summary": p["summary"], "state": n.State}
		// asset_ids is the structured "which assets this direction covers" signal for
		// dedup; fall back to legacy payload keys (target_ids plural, then target_id
		// single) so intents stored before the rename still surface their anchors.
		if tg, ok := p["asset_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_ids"]; ok && tg != nil {
			m["asset_ids"] = tg
		} else if tg, ok := p["target_id"]; ok && tg != nil && tg != "" {
			m["asset_ids"] = []any{tg}
		}
		if ps := parentsOf[n.ID]; len(ps) > 0 {
			m["parents"] = ps // 上游：本意图派生自哪些节点（多个事实可共同产生一个意图）
		}
		if ys := yieldsOf[n.ID]; len(ys) > 0 {
			m["yields"] = ys // 下游：本意图产生了哪些事实/发现
		}
		out = append(out, m)
	}
	return out
}

// ToolSet exposes the PG-backed dual graph (asset + exploration) to an LLM agent.
// One ToolSet is created per planner/worker run; per-run signals live here.
type ToolSet struct {
	as     *db.AssetStore   // asset store (optional; nil = asset tools not available)
	cs     *db.CompanyStore // company store (optional)
	ts     *db.ExplorationStore
	worker string
	taskID int64 // PG tasks.id; 0 when unknown (tests / orchestrator cross-task reads)
	// ownerNode is the exploration node that writes attach to: assets this run
	// touches get anchored to it as lineage/provenance (NOT visibility — the asset
	// graph is global and shared). Worker = its claimed intent; planner = begin root.
	ownerNode int64
	GoalMet   bool
	Reason    string
	writes    WriteCounts
	// killWork, if set, terminates a running work by intent id (engine callback,
	// wired by the planner). nil = the kill_work tool reports unavailable.
	killWork func(intentID int64) error
	// steerWork, if set, queues a mid-run course-correction for the work running an
	// intent id (engine callback, wired by the planner): the worker injects it before
	// its next tool call and re-plans, without being killed. nil = tool unavailable.
	steerWork func(intentID int64, msg string) error
	// enrich, if set, receives async auto-completion triggers (DNS resolve for a
	// domain, HTTP probe for a site). nil = no engine enrichment.
	enrich EnrichTrigger
	// notify, if set, wakes the task's planner after a graph change that should be
	// re-planned promptly (currently: a new hint). nil = no wake (the hint is still
	// stored and read on the next round triggered by other events). debounced.
	notify func()
	// kb, if set, enables search_knowledge / list_knowledge_categories over the
	// two-layer knowledge base (global + this task). nil = tools report "not enabled".
	kb *knowledge.Service
	// resolveTraffic, if set, resolves a finding's reproduction steps to real recorded
	// traffic exchange ids AT RECORD TIME (so the finding's steps carry jump-to-traffic
	// links without view-time guessing). Input = the raw reproduction JSON; returns the
	// same shape with each step's exchange_id filled where it matched. nil = skip.
	resolveTraffic func(taskID int64, repro json.RawMessage) json.RawMessage
}

// SetNotify wires the planner-wake callback (see ToolSet.notify). Set by callers
// that hold the task handle (main-agent chat, cross-task orchestration).
func (t *ToolSet) SetNotify(fn func()) { t.notify = fn }

// EnrichTrigger is the enrichment engine seen from the tool layer (see package
// enrich). Kept as an interface here to avoid coupling agent → enrich.
type EnrichTrigger interface {
	ResolveDomain(id int64, host string)
	ProbeSite(id int64, url string)
}

// WriteCounts breaks down what a worker persisted this run, by node kind, so the
// engine can log an accurate "wrote back" summary instead of lumping assets and
// findings under "facts" (record_fact → Facts, insert_assets → Assets,
// report_finding → Findings; each element of a batch counts once).
type WriteCounts struct {
	Facts    int
	Assets   int
	Findings int
}

// Total is every node persisted this run, regardless of kind — the
// "explored but persisted nothing" signal (Total == 0).
func (w WriteCounts) Total() int { return w.Facts + w.Assets + w.Findings }

// String renders the per-kind breakdown for logs, e.g. "事实1 资产25 漏洞0".
func (w WriteCounts) String() string {
	return fmt.Sprintf("facts=%d assets=%d findings=%d", w.Facts, w.Assets, w.Findings)
}

// Writes reports what this run wrote back, split by node kind (so the engine can
// tell "explored but persisted nothing" apart from a completed intent, and log an
// honest breakdown instead of calling assets/findings "facts").
func (t *ToolSet) Writes() WriteCounts { return t.writes }

func NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet {
	t := &ToolSet{ts: ts, worker: worker}
	if ts != nil { // auto-wire the knowledge base off the store's DB handle
		t.kb = knowledge.NewService(ts.DB())
	}
	return t
}

// SetTaskID sets the PG task id on this ToolSet so that report_finding can
// dual-write to the standalone findings table (which survives task deletion).
func (t *ToolSet) SetTaskID(id int64) { t.taskID = id }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided;
// nil = no linkage — reproduction steps are stored verbatim without exchange ids).
func (t *ToolSet) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	t.resolveTraffic = fn
}

// Cross-task reuse: exported accessors returning the per-task tool logic bound to
// THIS ToolSet's store. Host-side orchestration tools build a ToolSet for an
// arbitrary task, then Call these — so cross-task reads/hint reuse the exact
// same logic as the in-task tools. (readTool ignores ToolContext, so Call(…,nil)
// is safe; add_hint is a writeTool but also doesn't deref the context here.)
func (t *ToolSet) GraphOverviewTool() actool.CoreTool      { return t.graphOverview() }
func (t *ToolSet) ListFindingsTool() actool.CoreTool       { return t.listFindings() }
func (t *ToolSet) GetWorkerTraceTool() actool.CoreTool     { return t.getWorkerTrace() }
func (t *ToolSet) ListWorkerTracesTool() actool.CoreTool   { return t.listWorkerTraces() }
func (t *ToolSet) SearchWorkerTracesTool() actool.CoreTool { return t.searchAllWorkerTraces() }
func (t *ToolSet) AddHintTool() actool.CoreTool            { return t.addHint() }

// SetEnrich wires the async enrichment engine (DNS/HTTP auto-completion).
func (t *ToolSet) SetEnrich(e EnrichTrigger) { t.enrich = e }

// SetOwnerNode sets the exploration node that writes anchor to (worker: its
// intent node; planner/main: the begin root). Assets created/referenced while
// ownerNode is set are anchored to it as lineage (not visibility).
func (t *ToolSet) SetOwnerNode(id int64) { t.ownerNode = id }

// anchorOwner records a lineage edge from this run's owner node to an asset
// (no-op if unset). Provenance only — the asset graph is global and shared, so
// this no longer affects which assets a task can read.
func (t *ToolSet) anchorOwner(assetID int64) {
	if t.ownerNode > 0 && assetID > 0 {
		_ = t.ts.Anchor(t.ownerNode, assetID)
	}
}

// pid parses an id that may arrive as a JSON number or string ("" / 0 → 0).
func pid(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return v
	}
	return 0
}

// pidList parses a list of ids (number|string), dropping zeros/invalids.
func pidList(raw []json.RawMessage) []int64 {
	var out []int64
	for _, r := range raw {
		if v := pid(r); v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}
func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func intp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func idp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func writeTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func jsonResult(v any) (actool.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(string(b)), nil
}

// --- read tools (planner + worker) ---

func (t *ToolSet) graphOverview() actool.CoreTool {
	return readTool("graph_overview",
		"(Exploration graph) distilled situation summary: asset counts, sites without endpoints, frontier, findings, hints (strategic hints from humans/main agent — must be factored in when generating intents). Call this first when planning.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			return jsonResult(t.graphOverviewData())
		})
}

// graphOverviewData computes the distilled situational snapshot shared by the
// graph_overview tool and the planner's wake-up prompt (which pre-injects it so
// the model needn't spend a turn calling the tool — every plan round starts with
// an empty context and always needs this first).
func (t *ToolSet) graphOverviewData() map[string]any {
	{
		out := map[string]any{}
		// goals summary folded in so the planner needn't call list_goals each round.
		goals, _ := t.ts.ListByKind(db.KindGoal, 100)
		gsum := make([]map[string]any, 0, len(goals))
		for _, g := range goals {
			var p map[string]any
			_ = json.Unmarshal(g.Payload, &p)
			gsum = append(gsum, map[string]any{"id": g.ID, "state": g.State, "text": p["text"]})
		}
		out["goals"] = gsum
		// hints: 人类/主 agent 通过 add_hint 挂上图的战略提示；folded in so the
		// planner reads them every round when generating intents (否则只写不读).
		hints, _ := t.ts.ListByKind(db.KindHint, 50)
		hsum := make([]map[string]any, 0, len(hints))
		for _, h := range hints {
			var p map[string]any
			_ = json.Unmarshal(h.Payload, &p)
			hsum = append(hsum, map[string]any{"id": h.ID, "state": h.State, "text": p["text"]})
		}
		out["hints"] = hsum
		// lineage from the exploration edges: an intent's parents (what it
		// derived_from — possibly several facts combined) and its yields (the
		// facts/findings it produced). factFrom maps a fact → the intent that
		// produced it. This is the relationship layer the flat lists lacked.
		edges, _ := t.ts.Edges(5000)
		parentsOf := map[int64][]int64{}
		yieldsOf := map[int64][]int64{}
		factFrom := map[int64]int64{}
		for _, e := range edges {
			switch e.Rel {
			case db.RelDerivedFrom, db.RelSpawns: // upstream: derived_from (fact/finding/intent→intent) or spawns (origin fact→goal, legacy begin→intent)
				parentsOf[e.To] = append(parentsOf[e.To], e.From)
			case db.RelYields: // intent --yields--> fact/finding
				yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
				factFrom[e.To] = e.From
			}
		}
		fr, _ := t.ts.Frontier(100)
		out["open_intents"] = compactIntents(fr, parentsOf, yieldsOf)
		all, _ := t.ts.ListByKind(db.KindIntent, 300)
		var running, recentDone []*db.Node
		for _, n := range all {
			switch n.State {
			case "running":
				running = append(running, n)
			case "done", "blocked", "exhausted":
				if len(recentDone) < 15 {
					recentDone = append(recentDone, n)
				}
			}
		}
		out["running_intents"] = compactIntents(running, parentsOf, yieldsOf)
		out["recent_done_intents"] = compactIntents(recentDone, parentsOf, yieldsOf)
		out["frontier_open"] = len(fr)
		// findings (confirmed vulns) and facts (worker exploration results) are
		// now distinct node kinds. recent_facts surfaces fact summaries (esp.
		// negative results) so the planner sees them in one call; full content
		// via node_detail(id).
		vulnNodes, _ := t.ts.ListByKind(db.KindFinding, 1000)
		factNodes, _ := t.ts.ListByKind(db.KindFact, 1000) // newest first
		out["findings"] = len(vulnNodes)                   // 确认漏洞数（目标判定看它）
		out["facts"] = len(factNodes)                      // 探索事实/结论数（含否定结论）
		recentFacts := make([]map[string]any, 0, 20)
		for _, n := range factNodes {
			if len(recentFacts) >= 20 {
				break
			}
			m := compactNode(n)
			if from := factFrom[n.ID]; from > 0 {
				m["from_intent"] = from // 本事实由哪个意图产生
			}
			// confidence 带进概览：让规划者一眼看出哪条结论只是 inferred（尤其否定结论
			// 别当铁案）；evidence 较长，留给 node_detail(id)。
			var fp map[string]any
			if json.Unmarshal(n.Payload, &fp) == nil {
				if c, ok := fp["confidence"].(string); ok && c != "" {
					m["confidence"] = c
				}
			}
			recentFacts = append(recentFacts, m)
		}
		out["recent_facts"] = recentFacts // 最近事实的 {id, summary, from_intent, confidence?}，详情/证据用 node_detail(id)
		// the original task (root) so the planner always has it, not just the
		// decomposed goals.
		if description, goal, err := t.ts.Root(); err == nil {
			out["task"] = map[string]any{"description": description, "goal": goal}
		}
		return out
	}
}

// compactNode distills any exploration node to id + summary + state, dropping the
// big detail/evidence (fetch that on demand via node_detail).
func compactNode(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	return map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
}

// compactFinding is compactNode plus the vuln-specific vulnclass/severity.
func compactFinding(n *db.Node) map[string]any {
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	m := map[string]any{"id": n.ID, "state": n.State, "summary": p["summary"]}
	if vc, ok := p["vulnclass"]; ok && vc != nil && vc != "" {
		m["vulnclass"] = vc
	}
	if sv, ok := p["severity"]; ok && sv != nil && sv != "" {
		m["severity"] = sv
	}
	return m
}

func (t *ToolSet) listFindings() actool.CoreTool {
	return readTool("list_findings", "List [confirmed vulnerabilities] (compact: id+task_id+intent_id+vulnclass+severity+summary+status). task_id = the task the vuln belongs to; intent_id = the intent that produced it. Only vulnerabilities here — plain exploration facts are list_facts. Details via node_detail(id).",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKind(db.KindFinding, 500)
			intentOf, _ := t.ts.FindingIntents() // finding id -> 产生它的 intent id
			taskID := t.ts.ID()                  // exploration id = 任务 id（本 store 内所有 finding 同属）
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				m := compactFinding(n)
				m["task_id"] = taskID
				if iid, ok := intentOf[n.ID]; ok {
					m["intent_id"] = iid
				}
				out = append(out, m)
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listFacts() actool.CoreTool {
	return readTool("list_facts", "List [exploration facts/conclusions] (compact: id+summary+status) — the conclusions workers derived per intent (incl. negative ones like 'port closed' / 'not injectable'). Details via node_detail(id). Vulnerabilities are list_findings.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			f, _ := t.ts.ListByKind(db.KindFact, 500)
			out := make([]map[string]any, 0, len(f))
			for _, n := range f {
				out = append(out, compactNode(n))
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) nodeDetail() actool.CoreTool {
	return readTool("node_detail", "Fetch one [exploration-graph node] full content by id (fact/finding/intent/goal: summary + detail/evidence/PoC). Exploration-node ids only (the ids returned by list_facts / list_findings / graph_overview recent_facts). For [assets] use list_assets / asset_neighbors — asset ids are NOT exploration-node ids; never pass them here.",
		obj(map[string]any{"id": idp("exploration-graph node id (not an asset id)")}, "id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ID)
			if id <= 0 {
				return actool.Errorf("id 必填"), nil
			}
			n, err := t.ts.GetNode(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if n == nil {
				return actool.Errorf(fmt.Sprintf("exploration node %d not found. If you meant an asset, use list_assets / asset_neighbors (assets and exploration nodes are separate id spaces; asset ids cannot be passed to node_detail).", id)), nil
			}
			return jsonResult(n) // full payload incl. detail / evidence
		})
}

// --- planner write tools ---

// intentItem 是 add_intent 批量/单条的一条探索方向。
type intentItem struct {
	Summary   string            `json:"summary"`
	AssetIDs  []json.RawMessage `json:"asset_ids"`
	ParentIDs []json.RawMessage `json:"parent_ids"`
	Priority  int               `json:"priority"`
}

// addOneIntent 创建一条意图节点并连上游血缘，返回 id。
// 约束：意图只能锚在已确认知识上——每个 parent_id 必须是已存在的 fact/finding
// 节点（不能挂在别的意图/目标/提示上）。顶层全新方向留空 parent_ids，兜底连 origin fact。
// 这样"每个意图都连到 fact 节点、且是发现驱动而非凭空规划"从创建路径上被强制。
func (t *ToolSet) addOneIntent(it intentItem) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	// 先校验锚点（建节点前，避免坏锚点留下孤儿意图）。
	parents := pidList(it.ParentIDs)
	for _, pidv := range parents {
		n, err := t.ts.GetNode(pidv)
		if err != nil || n == nil {
			return 0, fmt.Errorf("parent_id %d does not exist: parent_ids must be ids of existing [fact/finding] nodes; for a top-level brand-new direction leave parent_ids empty", pidv)
		}
		if n.Kind != db.KindFact && n.Kind != db.KindFinding {
			return 0, fmt.Errorf("parent_id %d is a %q node and cannot anchor an intent: intents anchor only on confirmed [facts/findings], never on intents/goals/hints; for a top-level brand-new direction leave parent_ids empty", pidv, n.Kind)
		}
	}
	priority := it.Priority
	if priority == 0 {
		priority = 5
	}
	anchors := pidList(it.AssetIDs)
	payload := map[string]any{"summary": it.Summary}
	if len(anchors) > 0 {
		payload["asset_ids"] = anchors
	}
	id, err := t.ts.AddIntent(payload, priority, anchors, "planner")
	if err != nil {
		return 0, err
	}
	// upstream lineage: link each (validated) fact/finding parent → this intent, so
	// "multiple facts combine into one new intent" is expressible.
	for _, parent := range parents {
		_ = t.ts.Link(parent, db.RelDerivedFrom, id)
	}
	// a top-level intent (no explicit parent) connects to the origin fact, so every
	// intent still traces back to a fact node — at task start the only fact is the
	// origin, and the first intents derive from it.
	if len(parents) == 0 {
		if origin, _ := t.ts.OriginFactID(); origin > 0 {
			_ = t.ts.Link(origin, db.RelDerivedFrom, id)
		}
	}
	return id, nil
}

func (t *ToolSet) addIntent() actool.CoreTool {
	return writeTool("add_intent", "Create [exploration directions] in the frontier and link them into the exploration chain. Intents are open-ended exploration directions, not a fixed taxonomy — describe what to explore/verify/exploit in one free-form summary sentence.\n"+
		"★Prefer batching: submit the new directions screened this round in ONE intents array (fewer round-trips than per-item calls). Returns an ids array, same length/order as intents (failed items id=0, see errors). For a single item, omit intents and give the top-level summary.",
		obj(map[string]any{
			"intents":    map[string]any{"type": "array", "description": "[Prefer this] array of new exploration directions, processed in order. Each element has the same fields as the top-level fields below (summary/asset_ids/parent_ids/priority). Returns ids same length/order as this array.", "items": map[string]any{"type": "object"}},
			"summary":    str("[Single] one sentence describing this exploration direction: what + why. State the direction clearly; asset ids not required."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[Target asset ids] this direction tests/attacks (**pass whenever possible**; 0/1/many; list_assets ids, NOT exploration-node ids): which assets (sites/endpoints/parameters/hosts etc.) this direction targets. Whenever the direction centers on concrete assets you MUST pass them — it is the structured marker of 'which targets this exploration hits', used for coverage dedup and linking the intent into the asset chain. Leave empty only for pure global recon with no concrete target asset."},
			"parent_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Upstream anchor ids (optional; 0/1/many): which [confirmed facts/findings] this direction synthesizes from. **Only existing fact/finding node ids — never intents/goals/hints** — intents must anchor on confirmed knowledge: discovery-driven, not invented. Pass several when several facts combine into one new intent; leave empty for a top-level brand-new recon direction (auto-anchored to the task origin fact)."},
			"priority":   intp("priority 0-10, default 5"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Intents    []intentItem `json:"intents"`
				intentItem              // 单条模式：顶层 summary/asset_ids/parent_ids/priority
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Intents) > 0
			items := a.Intents
			if !batch {
				items = []intentItem{a.intentItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneIntent(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("intent created: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listGoals() actool.CoreTool {
	return readTool("list_goals", "List this task's goal nodes and their states (open/met), for judging completion.",
		obj(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			g, _ := t.ts.ListByKind(db.KindGoal, 100)
			return jsonResult(g)
		})
}

func (t *ToolSet) proveGoal() actool.CoreTool {
	return writeTool("prove_goal", "Call when you judge a finding/fact proves a goal met: links the evidence node to the goal node and marks the goal met.",
		obj(map[string]any{
			"goal_id":     idp("goal node id"),
			"evidence_id": idp("the finding/fact node id that proves it"),
			"reason":      str("why this evidence satisfies the goal"),
		}, "goal_id", "evidence_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				GoalID     json.RawMessage `json:"goal_id"`
				EvidenceID json.RawMessage `json:"evidence_id"`
				Reason     string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			goal, ev := pid(a.GoalID), pid(a.EvidenceID)
			if goal == 0 || ev == 0 {
				return actool.Errorf("goal_id and evidence_id are required"), nil
			}
			_ = t.ts.Link(ev, db.RelProves, goal)
			_ = t.ts.SetNodeState(goal, "met")
			// 每标记一个目标 met，就检查本任务是否【所有目标】都已 met；若是，自动判定
			// 任务完成（置 GoalMet），无需再依赖模型显式调 goal_met。
			if goals, err := t.ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
				allMet := true
				for _, g := range goals {
					if g.State != "met" {
						allMet = false
						break
					}
				}
				if allMet {
					t.GoalMet = true
					t.Reason = fmt.Sprintf("all %d goals met (last triggered by goal %d)", len(goals), goal)
					return actool.Text(fmt.Sprintf("goal %d marked met; all goals of this task are achieved — task auto-completed", goal)), nil
				}
			}
			return actool.Text(fmt.Sprintf("goal %d marked met", goal)), nil
		})
}

func (t *ToolSet) goalMet() actool.CoreTool {
	return writeTool("goal_met", "[Immediately ends the ENTIRE task] — call ONLY when you confirm [ALL goals of the task are truly met, overall wrap-up] (task-level completion; merely achieving one goal/one flag/one vulnerability does NOT count — use prove_goal for that). ⚠️ It is NOT for 'ending this planning round': with no new intents to dispatch, or while waiting for worker output, just end the round — do NOT call this tool (0 intents is perfectly normal). Prefer proving goals one by one with prove_goal; goal_met only bypasses per-goal proof for a global wrap-up.",
		obj(map[string]any{"reason": str("reason for completion (must be evidence the goals are truly met — never 'no new direction this round'-type round-ending reasons)")}, "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Reason string }
			_ = json.Unmarshal(in, &a)
			t.GoalMet = true
			t.Reason = a.Reason
			return actool.Text("acknowledged: goal marked met"), nil
		})
}

// --- worker write tools ---

func (t *ToolSet) addFinding() actool.CoreTool {
	return writeTool("report_finding", "MUST be called when you discover a vulnerability or confirm an exposure-class risk! Records one confirmed vulnerability or proven exposure/info-leak risk (unauthorized-reachable sensitive/admin/debug interfaces, exposed Swagger/config/backup, sensitive-data leaks — actually accessed with response evidence = confirmed). In task context intent_id is required (the currently executing intent id); in session context it may be omitted.",
		obj(map[string]any{
			"vulnclass": str("vulnerability class"),
			"severity":  str("critical|high|medium|low"),
			"summary":   str("finding summary"),
			"intent_id": idp("intent id that produced this finding (required in task context; optional in session context)"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "affected asset ids (optional; 0/1/many): parameters/endpoints/sites etc. Fill all when one vuln affects several; omit for pure observation."},
			"evidence":  str("evidence/PoC text"),
			"reproduction": map[string]any{
				"type":        "object",
				"description": "[Strongly recommended] structured reproduction — for human reproduction from zero and report delivery. Each step's request as a [standard HTTP request message] (not curl/commands), response as [status line + key body] (no '...' eliding key content), all verbatim from requests/responses you actually executed this run — never rewritten or fabricated; you just did it and know each step best.",
				"properties": map[string]any{
					"entry_point":   str("the key interface that triggers the vuln (method+URL), e.g. POST /user/validate/otp/forgetPasswordVerify"),
					"prerequisites": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "prerequisites: accounts/roles/sessions/prior steps needed. If a test account is required, state [how to register] (endpoint + key request points) — reproducible from zero."},
					"steps": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
						"request":  str("the step's real request as a [standard HTTP request message]: request line (METHOD /path?query HTTP/1.1) + key headers (Host/Content-Type/Cookie etc.) + blank line + body, verbatim from what you actually sent. [Do NOT write curl/python/shell commands] — even if executed via curl, reconstruct the equivalent HTTP message. Only when the step truly is not HTTP (direct DB connection, locally generated token) write the actual invocation prefixed with 'non-HTTP:'."),
						"response": str("the step's real response as an [HTTP response]: status line (HTTP/1.1 200 OK) + key headers + key body fragment, verbatim from the real return. [Do NOT elide the content that proves the point with '...']; for long responses keep only the fragments that locate this traffic and prove the vuln (echo/token/error etc.)."),
						"expected": str("the step's expected outcome/conclusion (status code + key field, one sentence)"),
						"proves":   str("what this step proves"),
					}}, "description": "ordered reproduction steps (entry to proof); each as [standard HTTP request message + key response] (not curl/commands; no '...' elision in responses) so they auto-link to the recorded real traffic packets, with one-click jump and screenshots"},
					"provenance": str("which exploration/intent discovered this vuln and which prior results it depends on (exploit-chain origin)"),
				},
			},
		}, "vulnclass", "severity", "summary"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass, Severity, Summary, Evidence string
				IntentID                               json.RawMessage   `json:"intent_id"`
				AssetIDs                               []json.RawMessage `json:"asset_ids"`
				Reproduction                           json.RawMessage   `json:"reproduction"`
			}
			_ = json.Unmarshal(in, &a)
			payload := map[string]any{"vulnclass": a.VulnClass, "severity": a.Severity, "summary": a.Summary,
				"evidence": map[string]any{"by": t.worker, "poc": a.Evidence}}
			repro := a.Reproduction
			if len(repro) > 2 { // "{}" is 2 bytes; only carry a real recipe
				// Resolve steps → real traffic exchange ids at record time (host callback),
				// so the stored finding's steps carry jump-to-traffic links up front.
				if t.resolveTraffic != nil && t.taskID > 0 {
					if r := t.resolveTraffic(t.taskID, repro); len(r) > 2 {
						repro = r
					}
				}
				payload["reproduction"] = repro
			}
			var anchors []int64
			for _, raw := range a.AssetIDs {
				if p := pid(raw); p > 0 {
					anchors = append(anchors, p)
				}
			}
			var id int64
			if t.ts != nil {
				var err error
				id, err = t.ts.AddNode(db.KindFinding, payload, 9, "confirmed", t.worker, anchors)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if intent := pid(a.IntentID); intent > 0 {
					_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> finding
				}
				_, _ = t.ts.AddStandaloneFinding(t.taskID, id, a.VulnClass, a.Severity, a.Summary, a.Evidence, t.worker, anchors)
				if len(repro) > 2 { // 就地记录的结构化复现过程(agent 测完即填,请求逐字真实)
					_ = t.ts.SetFindingReproduction(id, repro)
				}
			} else {
				// conversation context: no exploration store available, cannot record finding
				return actool.Errorf("report_finding requires task context (exploration store not initialized)"), nil
			}
			t.writes.Findings++
			return actool.Text(fmt.Sprintf("finding recorded: %d", id)), nil
		})
}

// recordFact writes a general exploration RESULT/conclusion (not a vuln, not a
// new asset) into the EXPLORATION graph, chained to the intent that produced it.
// This is the home for observations and — importantly — negative results
// ("port closed", "param not injectable", "no login found"). Such conclusions
// must NOT be stuffed into the asset graph via upsert_asset.
// factItem 是 record_fact 批量/单条的一条事实。
type factItem struct {
	Summary    string            `json:"summary"`
	Detail     string            `json:"detail"`
	Evidence   string            `json:"evidence"`   // 一行关键证据（命令+关键输出行），支撑结论、便于事后核对
	Confidence string            `json:"confidence"` // observed（直接看到）| inferred（据现象推断）
	IntentID   json.RawMessage   `json:"intent_id"`
	AssetIDs   []json.RawMessage `json:"asset_ids"`
}

// recordOneFact 写一条 fact 节点并连到意图（intent→yields→fact）。defaultIntent 为
// 批量时的默认意图（本条未给 intent_id 时用）。
func (t *ToolSet) recordOneFact(it factItem, defaultIntent int64) (int64, error) {
	if strings.TrimSpace(it.Summary) == "" {
		return 0, fmt.Errorf("summary must not be empty")
	}
	payload := map[string]any{"summary": it.Summary}
	if it.Detail != "" {
		payload["detail"] = it.Detail
	}
	if e := strings.TrimSpace(it.Evidence); e != "" {
		payload["evidence"] = e
	}
	if c := strings.TrimSpace(it.Confidence); c != "" {
		payload["confidence"] = c
	}
	// a fact is its OWN node kind (distinct from a vuln finding).
	id, err := t.ts.AddNode(db.KindFact, payload, 5, "confirmed", t.worker, pidList(it.AssetIDs))
	if err != nil {
		return 0, err
	}
	intent := pid(it.IntentID)
	if intent <= 0 {
		intent = defaultIntent
	}
	if intent > 0 {
		_ = t.ts.Link(intent, db.RelYields, id) // chain: intent -> fact
	}
	t.writes.Facts++
	return id, nil
}

func (t *ToolSet) recordFact() actool.CoreTool {
	return writeTool("record_fact", "Write an exploration [fact/conclusion] into the exploration graph, linked to the intent that produced it (intent_id). For recording exploration results — both [positive conclusions] like fingerprints/enumeration and [negative ones] like 'port closed' / 'parameter not injectable' / 'no login entry found'.\n"+
		"⚠️Coalesce the observations of one exploration into [ONE fact] — do not split; whenever observations can merge into one fact, use one: summary = one synthesizing sentence for this conclusion, detail = the specifics (may hold several concrete items). Example: a fingerprinting intent → one fact {summary:'identified the tech stack and response traits of site X', detail:'nginx 1.25 / Vue3 / 200 / title=.. / body_len=..'} — NOT one fact each for status code, fingerprint, title. One intent usually yields one fact; over-splitting bloats the graph unboundedly.\n"+
		"★The facts array writes several [genuinely different] conclusions at once (each may omit intent_id, defaulting to the top-level intent_id). Returns ids same length/order as facts.\n"+
		"⚠️Write only conclusions you [actually saw] in tool output — never make things up. evidence and confidence exist to keep inaccurate conclusions from polluting the graph:\n"+
		"  · evidence = the [one] key line supporting this conclusion (command + the one or two output lines that prove it best), **keep it terse** — details already live in detail; do not paste long output here.\n"+
		"  · confidence = observed (directly seen in output) | inferred (deduced from phenomena).\n"+
		"  · **Negative conclusions** (not injectable / port closed / no entry found etc.) especially need evidence and an honest confidence — they make the planner abandon a direction, and a wrong negative is costly; probed only once or weak evidence → mark inferred, never treat as hard fact.",
		obj(map[string]any{
			"facts":      map[string]any{"type": "array", "description": "[Use when there are several different conclusions] facts array; element fields are the same as the top-level fields below (summary/detail/evidence/confidence/intent_id/asset_ids); omit intent_id to use the top-level one. Returns ids same length/order.", "items": map[string]any{"type": "object"}},
			"summary":    str("the [one synthesizing sentence] for this exploration's conclusion (a summary of detail)"),
			"intent_id":  idp("intent id that produced this fact (the intent you were assigned; batch default)"),
			"detail":     str("the fact's specifics: put this exploration's multiple observations here"),
			"evidence":   str("[One] key line of evidence: command + the one or two output lines that prove the conclusion best. Keep it terse — no long output dumps (details go in detail)."),
			"confidence": str("observed (directly seen in output) | inferred (deduced from phenomena). Always label negative conclusions honestly."),
			"asset_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "related asset ids (optional; 0/1/many): which assets this fact concerns"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Facts    []factItem `json:"facts"`
				factItem            // 单条模式 + 批量默认 intent_id
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Facts) > 0
			items := a.Facts
			if !batch {
				items = []factItem{a.factItem}
			}
			defaultIntent := pid(a.factItem.IntentID) // 顶层 intent_id = 批量默认

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.recordOneFact(it, defaultIntent)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("fact recorded: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

type hintItem struct {
	Text     string            `json:"text"`
	AssetIDs []json.RawMessage `json:"asset_ids"`
}

// addOneHint 挂一条 hint 节点(active/human)到探索图,可锚定资产,返回 id。
func (t *ToolSet) addOneHint(it hintItem) (int64, error) {
	if strings.TrimSpace(it.Text) == "" {
		return 0, fmt.Errorf("text must not be empty")
	}
	var anchors []int64
	for _, raw := range it.AssetIDs {
		if tid := pid(raw); tid > 0 {
			anchors = append(anchors, tid)
		}
	}
	id, err := t.ts.AddNode(db.KindHint, map[string]any{"text": it.Text}, 0, "active", "human", anchors)
	if err == nil && t.notify != nil {
		t.notify() // wake the planner so the new hint is read promptly (debounced)
	}
	return id, err
}

func (t *ToolSet) addHint() actool.CoreTool {
	return writeTool("add_hint", "Attach a strategic hint from the human/main agent to the exploration graph; the planner reads it when generating intents next time.\n"+
		"★Prefer batching: submit several hints in ONE hints array (fewer round-trips than per-item calls). Returns ids same length/order (failed items id=0, see errors). For a single hint, omit hints and give the top-level text.",
		obj(map[string]any{
			"hints":     map[string]any{"type": "array", "description": "[Prefer this] array of new hints, processed in order. Each element has the same fields as the top-level fields below (text/asset_ids). Returns ids same length/order.", "items": map[string]any{"type": "object"}},
			"text":      str("[Single] hint text, e.g. 'focus on post-auth endpoints'"),
			"asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "anchored asset ids (optional; 0/1/many)"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Hints    []hintItem `json:"hints"`
				hintItem            // 单条模式：顶层 text/asset_ids
			}
			_ = json.Unmarshal(in, &a)
			batch := len(a.Hints) > 0
			items := a.Hints
			if !batch {
				items = []hintItem{a.hintItem}
			}

			ids := make([]int64, len(items))
			errs := map[string]string{}
			for i, it := range items {
				id, err := t.addOneHint(it)
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				ids[i] = id
			}

			if !batch { // 单条：保持原返回
				if e, bad := errs["0"]; bad {
					return actool.Errorf(e), nil
				}
				return actool.Text(fmt.Sprintf("hint added: %d", ids[0])), nil
			}
			out := map[string]any{"ids": ids}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

// killWorkTool lets the planner terminate a single running work (by intent id).
func (t *ToolSet) killWorkTool() actool.CoreTool {
	return writeTool("kill_work", "Terminate a running intent (work). Use to stop a derailed/pointless exploration; the terminated intent is marked stopped and never auto-reclaimed. Check get_worker_output first to see what it is doing.",
		obj(map[string]any{"intent_id": idp("intent id to terminate (= work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.killWork == nil {
				return actool.Errorf("kill_work currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			if err := t.killWork(id); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("termination signal sent to the work of intent %d", id)), nil
		})
}

// steerWorkTool lets the planner inject a mid-run course-correction into a running
// work WITHOUT killing it: the message reaches the worker before its next tool call,
// which re-plans its next step (already-gathered context is kept). For in-intent
// nudges ("停做 X、聚焦 Y"); if the whole direction is wrong use kill_work + a new intent.
func (t *ToolSet) steerWorkTool() actool.CoreTool {
	return writeTool("steer_work", "Inject a steering instruction into a running intent (work) in real time without interrupting it or losing progress: the worker receives it before its next action and adjusts. For within-intent course corrections like 'stop X, focus Y'; if the whole direction is wrong, use kill_work and a new intent instead. Check get_worker_output first.",
		obj(map[string]any{
			"intent_id": idp("intent id to steer (= work handle)"),
			"message":   str("steering instruction for the worker: state clearly what to stop and what to switch to"),
		}, "intent_id", "message"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.steerWork == nil {
				return actool.Errorf("steer_work currently unavailable"), nil
			}
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
				Message  string          `json:"message"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			if strings.TrimSpace(a.Message) == "" {
				return actool.Errorf("message is required"), nil
			}
			if err := t.steerWork(id, a.Message); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(fmt.Sprintf("steering instruction injected into the work of intent %d (effective on the next step)", id)), nil
		})
}

// getWorkerOutput returns a work's final (or截至中止时的) conclusion text by intent id.
func (t *ToolSet) getWorkerOutput() actool.CoreTool {
	return readTool("get_worker_output", "Fetch an intent's (work's) final output conclusion. A normally finished work returns its summary; a stopped/aborted work returns its last output up to termination (terminated=true).",
		obj(map[string]any{"intent_id": idp("intent id (= work handle)")}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			acts, _, err := t.ts.ActivityList(&id, 0, 1000)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var chosen, fallback *db.Activity
			for i := range acts {
				switch acts[i].Kind {
				case "result":
					chosen = &acts[i]
					fallback = &acts[i]
				case "text":
					fallback = &acts[i]
				}
			}
			pick, terminated := chosen, false
			if pick == nil {
				pick, terminated = fallback, true
			}
			if pick == nil {
				return actool.Text("(this work has no output yet)"), nil
			}
			detail, _ := t.ts.ActivityDetail(pick.ID)
			if detail == "" {
				detail = pick.Summary
			}
			return jsonResult(map[string]any{
				"intent_id": id, "worker_name": pick.Worker, "final_text": detail,
				"summary": pick.Summary, "is_error": pick.IsError, "terminated": terminated,
			})
		})
}

// traceSteps renders summary-only trace rows, re-truncating each summary to 100
// chars — the stored summary is capped at 200 for the UI transcript; the trace
// tools want it tighter since a whole work's step list is many rows.
func traceSteps(acts []db.Activity) []map[string]any {
	steps := make([]map[string]any, 0, len(acts))
	for i := range acts {
		steps = append(steps, map[string]any{
			"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
			"is_error": acts[i].IsError, "summary": firstLine(acts[i].Summary, 100),
		})
	}
	return steps
}

// getWorkerTrace exposes a work's execution PROCESS (not just its final output):
// list step summaries, keyword-search within one work, or pull full detail of a
// few specific steps. Thinking steps are excluded everywhere.
func (t *ToolSet) getWorkerTrace() actool.CoreTool {
	return readTool("get_worker_trace",
		"Inspect an intent's (work's) [execution process] (unlike get_worker_output, which only gives the final conclusion). Three usages:\n"+
			"① intent_id only → the work's per-step summary stream (summary≤100 chars, with step_id; action outline only, no full outputs);\n"+
			"② intent_id + q → only step summaries matching the keyword (searches summaries and full outputs; still summaries only — use ③ for content);\n"+
			"③ intent_id + step_ids (max 5) → the full content (detail) of those steps.\n"+
			"Typical flow: locate suspicious step_ids with ①/②, then fetch their full outputs with ③. Thinking steps excluded.",
		obj(map[string]any{
			"intent_id": idp("intent id (= work handle)"),
			"q":         str("keyword: return only steps whose summary/full output matches (optional; mutually exclusive with step_ids)"),
			"step_ids":  map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "step_ids to fetch in full (from ①/② returns; max 5 per call)"},
			"limit":     intp("return cap for the summary stream/search (optional)"),
		}, "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID json.RawMessage   `json:"intent_id"`
				Q        string            `json:"q"`
				StepIDs  []json.RawMessage `json:"step_ids"`
				Limit    int               `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.IntentID)
			if id <= 0 {
				return actool.Errorf("intent_id is required"), nil
			}
			// ③ detail drill-down by step ids (max 5), thinking excluded by the store.
			if len(a.StepIDs) > 0 {
				var ids []int64
				for _, raw := range a.StepIDs {
					if v := pid(raw); v > 0 {
						ids = append(ids, v)
					}
				}
				if len(ids) > 5 {
					return actool.Errorf("step_ids max 5 per call (locate first without step_ids, then fetch in batches)"), nil
				}
				acts, err := t.ts.ActivityByIDs(ids)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				steps := make([]map[string]any, 0, len(acts))
				for i := range acts {
					steps = append(steps, map[string]any{
						"step_id": acts[i].ID, "kind": acts[i].Kind, "tool": acts[i].Tool,
						"is_error": acts[i].IsError, "detail": acts[i].Detail,
					})
				}
				return jsonResult(map[string]any{"intent_id": id, "steps": steps})
			}
			// ①/② summary stream, optionally keyword-filtered; 100-char summaries.
			var acts []db.Activity
			var err error
			if strings.TrimSpace(a.Q) != "" {
				acts, err = t.ts.ActivityTraceSearch(&id, a.Q, a.Limit)
			} else {
				acts, err = t.ts.ActivityTrace(id, a.Limit)
			}
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"intent_id": id, "steps": traceSteps(acts)})
		})
}

// searchAllWorkerTraces keyword-searches EVERY work's process in this task — for
// finding what a worker saw but never wrote back as a fact. Returns only matching
// summaries (≤100 chars), each tagged with its intent_id for follow-up drill-down.
func (t *ToolSet) searchAllWorkerTraces() actool.CoreTool {
	return readTool("search_all_worker_traces",
		"Keyword-search (q) across [ALL works' execution processes of this task] — to recover things a worker saw but never wrote into a fact (a path/token/error etc.)."+
			"Returns only matching steps' summaries (summary≤100 chars), each with intent_id; then fetch full content via get_worker_trace(intent_id, step_ids=[...]). Thinking steps excluded.",
		obj(map[string]any{
			"q":     str("keyword (searched across all work steps' summaries + full outputs)"),
			"limit": intp("return cap, default 100 (optional)"),
		}, "q"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Q) == "" {
				return actool.Errorf("q is required"), nil
			}
			acts, err := t.ts.ActivityTraceSearch(nil, a.Q, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			hits := make([]map[string]any, 0, len(acts))
			for i := range acts {
				var intent int64
				if acts[i].NodeID != nil {
					intent = *acts[i].NodeID
				}
				hits = append(hits, map[string]any{
					"intent_id": intent, "step_id": acts[i].ID, "worker": acts[i].Worker,
					"kind": acts[i].Kind, "tool": acts[i].Tool, "is_error": acts[i].IsError,
					"summary": firstLine(acts[i].Summary, 100),
				})
			}
			return jsonResult(map[string]any{"query": a.Q, "hits": hits})
		})
}

// listWorkerTraces gives a worker (which has no graph_overview and can't see the
// intent graph) a lightweight index of the works in this task — intent_id +
// one-line summary + state — so it can DISCOVER which works to inspect via
// get_worker_trace. Without this a worker only knows intent_ids that come back
// from search_all_worker_traces hits. Excludes still-open intents (not yet run →
// no process to inspect).
func (t *ToolSet) listWorkerTraces() actool.CoreTool {
	return readTool("list_worker_traces",
		"Index of [works (intents) that have run] in this task: intent_id + one-line direction (summary) + status."+
			"You (worker) cannot see the exploration graph; use this to find which works are worth reviewing — then get_worker_trace(intent_id) for steps, get_worker_trace(intent_id, step_ids=[...]) for details."+
			"Lists only executed ones (running/done/exhausted/blocked/stopped), not unstarted open intents. Note: your task boundary is still your own assigned intent — reading other works is only for reusing observations/avoiding duplicate labor.",
		obj(map[string]any{
			"q":     str("filter by summary keyword (optional)"),
			"limit": intp("return cap, default 50 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			limit := a.Limit
			if limit <= 0 {
				limit = 50
			}
			all, err := t.ts.ListByKind(db.KindIntent, 500)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Q))
			out := make([]map[string]any, 0, limit)
			for _, n := range all {
				switch n.State {
				case "running", "done", "exhausted", "blocked", "stopped": // has run → has a process
				default:
					continue
				}
				var p map[string]any
				_ = json.Unmarshal(n.Payload, &p)
				summary, _ := p["summary"].(string)
				if q != "" && !strings.Contains(strings.ToLower(summary), q) {
					continue
				}
				out = append(out, map[string]any{"intent_id": n.ID, "summary": summary, "state": n.State})
				if len(out) >= limit {
					break
				}
			}
			return jsonResult(map[string]any{"works": out})
		})
}

// PlannerTools is the read + intent-generation + goal-judgement tool set.
func (t *ToolSet) PlannerTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.listGoals(), t.addIntent(), t.proveGoal(), t.goalMet(),
		t.killWorkTool(), t.steerWorkTool(),
		// report_finding：规划态势研判时若自身已确证漏洞，可直接登记（与 worker 同工具）。
		t.addFinding(),
		// list_companies：查看企业列表 + scope + 资产数（拿 company_id / 理解归属范围）。
		t.listCompanies(),
		// 知识库：规划时检索评分规则/目标/通用方法论以校准探索意图。
		t.searchKnowledge(), t.listKnowledgeCategories(),
	}
}
