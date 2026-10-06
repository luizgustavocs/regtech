package engine

import (
	"encoding/json"
	"net/http"
)

type EngineHandler struct {
	repo *EngineRepository
}

func NewEngineHandler(repo *EngineRepository) *EngineHandler {
	return &EngineHandler{repo: repo}
}

type IngestInput struct {
	RuleKey  string `json:"rule_key"`
	Target   string `json:"target"`
	Evidence string `json:"evidence"`
}

// IngestFindingHandler recebe inputs técnicos da camada Detecta
func (h *EngineHandler) IngestFindingHandler(w http.ResponseWriter, r *http.Request) {
	var input IngestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if input.RuleKey == "" || input.Target == "" || input.Evidence == "" {
		http.Error(w, "Missing required fields: rule_key, target, evidence", http.StatusUnprocessableEntity)
		return
	}

	finding := &Finding{
		RuleKey:  input.RuleKey,
		Target:   input.Target,
		Evidence: input.Evidence,
	}

	if err := h.repo.SaveFinding(r.Context(), finding); err != nil {
		http.Error(w, "Internal logging failure", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(finding)
}

// GetReportHandler resolve a camada de Inferência e Explicabilidade
func (h *EngineHandler) GetReportHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Missing query parameter: target", http.StatusBadRequest)
		return
	}

	report, err := h.repo.GenerateAuditReport(r.Context(), target)
	if err != nil {
		http.Error(w, "Failed to compute legal correlation", http.StatusInternalServerError)
		return
	}

	if report == nil {
		report = []AuditReportItem{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(report)
}
