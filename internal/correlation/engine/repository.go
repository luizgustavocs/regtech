package engine

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type EngineRepository struct {
	db *pgxpool.Pool
}

func NewEngineRepository(db *pgxpool.Pool) *EngineRepository {
	return &EngineRepository{db: db}
}

// SaveFinding persiste a evidência técnica encontrada no banco
func (r *EngineRepository) SaveFinding(ctx context.Context, f *Finding) error {
	query := `
		INSERT INTO findings (rule_key, target, evidence) 
		VALUES ($1, $2, $3) 
		RETURNING id::text, created_at`

	err := r.db.QueryRow(ctx, query, f.RuleKey, f.Target, f.Evidence).Scan(&f.ID, &f.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to save technical finding: %w", err)
	}
	return nil
}

// GenerateAuditReport realiza a inferência correlacionando a falha com a matriz legal
func (r *EngineRepository) GenerateAuditReport(ctx context.Context, target string) ([]AuditReportItem, error) {
	query := `
        SELECT 
            f.id::text, f.rule_key, f.target, f.evidence, f.created_at,
            c.id::text, c.framework, c.section, c.description, c.criticality,
            ir.impact_score, ir.explanation
        FROM findings f
        INNER JOIN inference_rules ir ON f.rule_key = ir.rule_key
        INNER JOIN compliance_obligations c ON ir.obligation_id = c.id
        WHERE f.target = $1
        ORDER BY ir.impact_score DESC`

	rows, err := r.db.Query(ctx, query, target)
	if err != nil {
		return nil, fmt.Errorf("failed to execute inference engine query: %w", err)
	}
	defer rows.Close()

	var report []AuditReportItem

	for rows.Next() {
		var item AuditReportItem
		err := rows.Scan(
			&item.Finding.ID, &item.Finding.RuleKey, &item.Finding.Target, &item.Finding.Evidence, &item.Finding.CreatedAt,
			&item.Obligation.ID, &item.Obligation.Framework, &item.Obligation.Section, &item.Obligation.Description, &item.Obligation.Criticality,
			&item.ImpactScore, &item.Explanation,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit report row: %w", err)
		}
		report = append(report, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("row error during streaming report rows: %w", err)
	}

	return report, nil
}
