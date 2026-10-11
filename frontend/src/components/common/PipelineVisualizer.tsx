import React from 'react';
import type { FirewallVerdict } from '../../types';

interface PipelineVisualizerProps {
  verdict: FirewallVerdict | null;
  isAnalyzing?: boolean;
}

export const PipelineVisualizer: React.FC<PipelineVisualizerProps> = ({
  verdict,
  isAnalyzing = false,
}) => {
  const getStageState = (stageIndex: number) => {
    if (isAnalyzing) {
      return { class: 'active', status: 'Inspecting...' };
    }
    if (!verdict) {
      return { class: '', status: 'Standby' };
    }

    switch (stageIndex) {
      case 1: // Normalization
        return {
          class: 'passed',
          status: verdict.normalized_text ? 'Cleaned & Normalized' : 'Passed',
        };
      case 2: // Rule Engine
        if (verdict.threat_signals && verdict.threat_signals.length > 0) {
          return {
            class: verdict.verdict === 'BLOCK' ? 'blocked' : 'review',
            status: `${verdict.threat_signals.length} Signal(s)`,
          };
        }
        return { class: 'passed', status: '0 Violations' };
      case 3: // Threat Classifier
        if (verdict.threat_category !== 'NONE') {
          return {
            class: verdict.verdict === 'BLOCK' ? 'blocked' : 'review',
            status: verdict.threat_category,
          };
        }
        return { class: 'passed', status: 'Clean (None)' };
      case 4: // Risk Scoring
        return {
          class:
            verdict.risk_score >= 70
              ? 'blocked'
              : verdict.risk_score >= 35
              ? 'review'
              : 'passed',
          status: `Score: ${verdict.risk_score}/100`,
        };
      case 5: // Policy Decision
        if (verdict.verdict === 'BLOCK') {
          return { class: 'blocked', status: 'VERDICT: BLOCK' };
        }
        if (verdict.verdict === 'REVIEW') {
          return { class: 'review', status: 'VERDICT: REVIEW' };
        }
        return { class: 'passed', status: 'VERDICT: APPROVE' };
      case 6: // Execution Auth
        if (verdict.execution_token) {
          return { class: 'passed', status: 'Token Issued' };
        }
        return { class: 'blocked', status: 'Withheld (Fail-Closed)' };
      default:
        return { class: '', status: 'Standby' };
    }
  };

  const stages = [
    { num: 'STAGE 1', title: 'Input Normalization', desc: 'NFKC & Homoglyphs' },
    { num: 'STAGE 2', title: 'Rule-Engine Analysis', desc: 'Deterministic Regex' },
    { num: 'STAGE 3', title: 'Threat Classification', desc: 'Heuristics & Category' },
    { num: 'STAGE 4', title: 'Risk Scoring', desc: '0-100 Algorithm' },
    { num: 'STAGE 5', title: 'Policy Decision', desc: 'Authoritative Verdict' },
    { num: 'STAGE 6', title: 'Execution Authorization', desc: 'HMAC Cryptographic Gate' },
  ];

  return (
    <div className="card" style={{ marginTop: '1rem' }}>
      <div className="card-header" style={{ marginBottom: '0.5rem', paddingBottom: '0.4rem' }}>
        <div>
          <h3 className="card-title" style={{ fontSize: '0.9rem' }}>
            🛡️ Six-Stage Defensive Inspection Pipeline
          </h3>
          <p className="card-subtitle" style={{ fontSize: '0.74rem' }}>
            Multi-layered Blue-Team inspection boundary operating in &lt;1ms
          </p>
        </div>
      </div>

      <div className="pipeline-stepper" role="list" aria-label="Inspection Pipeline Stages">
        {stages.map((st, idx) => {
          const state = getStageState(idx + 1);
          return (
            <div
              key={st.num}
              role="listitem"
              className={`pipeline-stage ${state.class}`}
            >
              <div className="stage-num">{st.num}</div>
              <div className="stage-title">{st.title}</div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                {st.desc}
              </div>
              <div className="stage-status" style={{ marginTop: '0.35rem', fontWeight: 600 }}>
                {state.status}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
