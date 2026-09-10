import { AIProvider } from './providerInterface.js';
import { Finding, ScanRecord, AIAnalysis } from '../../types/index.js';

export class HeuristicAIProvider implements AIProvider {
  name = 'SentinelScan Heuristic Intelligence';

  async analyze(scan: ScanRecord, findings: Finding[]): Promise<AIAnalysis> {
    if (!findings || findings.length === 0) {
      return {
        provider: this.name,
        executive_summary: 'Insufficient evidence to formulate vulnerability assessments.',
        risk_narrative: 'No actionable findings were identified on the scoped target during this assessment.',
        remediation_roadmap: [],
      };
    }

    const criticals = findings.filter(f => f.severity === 'CRITICAL');
    const highs = findings.filter(f => f.severity === 'HIGH');
    const mediums = findings.filter(f => f.severity === 'MEDIUM');
    const lows = findings.filter(f => f.severity === 'LOW');
    const infos = findings.filter(f => f.severity === 'INFO');

    // Build Executive Summary
    let execSummary = `Security assessment completed for ${scan.target_hostname} (${scan.target_url}). `;
    execSummary += `Overall posture is rated as Grade ${scan.grade} with an overall risk rating of ${scan.risk_level} (Security Score: ${scan.security_score}/100). `;

    if (criticals.length > 0) {
      execSummary += `Immediate defensive action is required: ${criticals.length} CRITICAL severity vulnerability was detected, including: ${criticals.map(c => c.title).join('; ')}. `;
    } else if (highs.length > 0) {
      execSummary += `Elevated exposure observed: ${highs.length} HIGH severity finding(s) require prompt remediation: ${highs.map(h => h.title).slice(0, 3).join('; ')}. `;
    } else if (mediums.length > 0) {
      execSummary += `Moderate hardening opportunities discovered across HTTP header defense and transport security controls. `;
    } else {
      execSummary += `No critical or high-severity vulnerabilities were identified across scanned endpoints. Baseline security controls appear functional. `;
    }

    // Build Risk Narrative
    let riskNarrative = `Across ${scan.pages_scanned} audited page(s) and ${findings.length} normalized finding(s), the primary areas of exposure center around `;
    const categories = Array.from(new Set(findings.map(f => f.category)));
    riskNarrative += `${categories.slice(0, 3).join(', ')}. `;

    if (criticals.length > 0 || highs.length > 0) {
      riskNarrative += `Exploitation of these misconfigurations could compromise data confidentiality, session integrity, or expose application infrastructure to unauthorized cross-origin requests.`;
    } else {
      riskNarrative += `Adopting defense-in-depth mitigations will reinforce browser-side boundary enforcement and reduce reconnaissance value for external threat actors.`;
    }

    // Prioritized Remediation Roadmap
    const prioritizedFindings = [...criticals, ...highs, ...mediums, ...lows];
    const roadmap = prioritizedFindings.slice(0, 8).map((f, index) => ({
      priority: index + 1,
      title: f.title,
      action: f.remediation,
      target: f.url,
    }));

    return {
      provider: this.name,
      executive_summary: execSummary,
      risk_narrative: riskNarrative,
      remediation_roadmap: roadmap,
    };
  }
}
