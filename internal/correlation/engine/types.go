package engine

import "time"

// Camada Técnica (Detecta): Evidência física coletada pelo scanner
type Finding struct {
	ID        string    `json:"id"`
	RuleKey   string    `json:"rule_key"` // Ex: "MISSING_SECURE_COOKIES"
	Target    string    `json:"target"`   // Ex: "https://api.vulneravel.com"
	Evidence  string    `json:"evidence"` // Ex: "Set-Cookie header without Secure attribute"
	CreatedAt time.Time `json:"created_at"`
}

// Camada Normativa (Representa): O mapeamento abstrato de uma obrigação legal ou framework
type ComplianceObligation struct {
	ID          string `json:"id"`
	Framework   string `json:"framework"`   // Ex: "LGPD", "MCI", "OWASP"
	Section     string `json:"section"`     // Ex: "Art. 46", "A05:2021"
	Description string `json:"description"` // Ex: "Dever de segurança e boas práticas"
	Criticality string `json:"criticality"` // Ex: "CRITICAL", "HIGH", "MEDIUM"
}

// Camada de Inferência (Relaciona): O elo entre a falha técnica e a violação legal
type InferenceRule struct {
	ID           string `json:"id"`
	RuleKey      string `json:"rule_key"`      // Liga ao Finding
	ObligationID string `json:"obligation_id"` // Liga à ComplianceObligation
	ImpactScore  int    `json:"impact_score"`  // 1 a 100
}

// Camada de Explicabilidade: O resultado consolidado para auditorias enterprise
type AuditReportItem struct {
	Finding     Finding              `json:"finding"`
	Obligation  ComplianceObligation `json:"obligation"`
	ImpactScore int                  `json:"impact_score"`
	Explanation string               `json:"explanation"` // Responde: "Por que isso gerou risco LGPD?"
}
