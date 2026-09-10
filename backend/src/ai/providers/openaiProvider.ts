import { AIProvider } from './providerInterface.js';
import { Finding, ScanRecord, AIAnalysis } from '../../types/index.js';
import { config } from '../../config.js';

export class OpenAIProvider implements AIProvider {
  name = 'OpenAI-Compatible Security Advisor';

  async analyze(scan: ScanRecord, findings: Finding[]): Promise<AIAnalysis> {
    if (!config.openaiApiKey) {
      throw new Error('OPENAI_API_KEY is not configured');
    }

    if (!findings || findings.length === 0) {
      return {
        provider: this.name,
        executive_summary: 'Insufficient evidence.',
        risk_narrative: 'Insufficient evidence.',
        remediation_roadmap: [],
      };
    }

    const sanitizedSummary = {
      target: scan.target_hostname,
      score: scan.security_score,
      grade: scan.grade,
      risk_level: scan.risk_level,
      findings: findings.map(f => ({
        title: f.title,
        severity: f.severity,
        category: f.category,
        evidence: f.evidence,
        remediation: f.remediation,
      })),
    };

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.openaiApiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: 'You are an application security auditor. ONLY use the provided evidence. Never invent vulnerabilities. Return JSON with keys: executive_summary, risk_narrative, remediation_roadmap.',
          },
          {
            role: 'user',
            content: JSON.stringify(sanitizedSummary),
          },
        ],
        response_format: { type: 'json_object' },
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const content = data.choices[0].message.content;
    const parsed = JSON.parse(content);

    return {
      provider: this.name,
      executive_summary: parsed.executive_summary || 'Analysis complete.',
      risk_narrative: parsed.risk_narrative || 'Evaluation finished.',
      remediation_roadmap: Array.isArray(parsed.remediation_roadmap) ? parsed.remediation_roadmap : [],
    };
  }
}
