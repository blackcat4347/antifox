package report

// Retroactive finding extraction: pull confirmed vulnerabilities out of a task's
// agent transcript (synthesis + worker conclusions) that were described but never
// recorded via report_finding — so they can be back-filled as finding nodes.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"antifox/db"
)

// ExtractedFinding is one vuln pulled from the transcript.
type ExtractedFinding struct {
	VulnClass string `json:"vulnclass"`
	Severity  string `json:"severity"` // high|medium|low
	Summary   string `json:"summary"`
	Target    string `json:"target"`
	Evidence  string `json:"evidence"`
}

const sysExtract = "You are a senior penetration-testing expert. Extract [confirmed vulnerabilities] from penetration-test execution/summary records. Output strict JSON only, no markdown fences. Evidence must keep the real verbatim text from the records — never fabricate."

const userExtract = `From the following penetration-test execution and summary records, extract all [confirmed vulnerabilities] and [proven exposures / information-leak risks] (excluding unverified guesses and negative conclusions).

Already-recorded vulnerabilities (do not output these again):
%s
Execution/summary records:
%s

Requirements:
- One confirmed vulnerability per entry: vulnclass (type/name, e.g. "Stored XSS", "Hard-coded credentials", "Unauthorized access"), severity (critical|high|medium|low; critical = directly causes full system/data compromise), summary (one-sentence summary including the affected object), target (affected host or URL), evidence (key PoC/request/command/response verbatim, keep real content).
- Extract only vulnerabilities/exposures the records **explicitly verified**; skip items semantically identical to the "already recorded" list above.
- **Exposure/info-leak class must also be extracted**: unauthorized-reachable sensitive/admin/debug interfaces, Swagger/API docs, exposed config/backup/source files, sensitive-data leaks etc. that the records actually accessed with response evidence — severity by sensitivity (ordinary info leak=low, unauth-reachable sensitive/admin interface=medium, takeover-able or yielding credentials/keys=high). Still exclude pure speculation (version/CVE matches, "looks injectable"); a merely "existing interface" without unauthorized exposure does not count.
- If there are no new vulnerabilities/exposures, output an empty findings array.

Output JSON only: {"findings":[{"vulnclass":"...","severity":"high","summary":"...","target":"...","evidence":"..."}]}`

// ExtractFindings asks the active LLM to extract confirmed vulns from the
// transcript, excluding ones already recorded (passed as short labels).
func ExtractFindings(ctx context.Context, pg *db.DB, transcript string, existing []string) ([]ExtractedFinding, error) {
	if strings.TrimSpace(transcript) == "" {
		return nil, fmt.Errorf("no transcript to analyze")
	}
	var ex strings.Builder
	for _, e := range existing {
		ex.WriteString("- ")
		ex.WriteString(e)
		ex.WriteString("\n")
	}
	if ex.Len() == 0 {
		ex.WriteString("(none)\n")
	}
	raw, err := complete(ctx, pg, sysExtract, fmt.Sprintf(userExtract, ex.String(), transcript), 4000)
	if err != nil {
		return nil, err
	}
	var out struct {
		Findings []ExtractedFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("failed to parse AI output")
	}
	return out.Findings, nil
}
