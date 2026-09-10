import { AIProvider } from './providerInterface.js';
import { Finding, ScanRecord, AIAnalysis } from '../../types/index.js';
import { config } from '../../config.js';

export class GeminiAIProvider implements AIProvider {
  name = 'Google Gemini Security Advisor';

  async analyze(scan: ScanRecord, findings: Finding[]): Promise<AIAnalysis> {
    if (!config.geminiApiKey) {
      throw new Error('GEMINI_API_KEY is not configured');
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
      pages_scanned: scan.pages_scanned,
      findings: findings.map(f => ({
        title: f.title,
        severity: f.severity,
        category: f.category,
        evidence: f.evidence,
        remediation: f.remediation,
      })),
    };

    const prompt = `You are a certified senior application security analyst reviewing an authorized penetration test / vulnerability assessment.
Strict Rules:
1. You must ONLY use the provided sanitized scanner evidence below. Never invent or hallucinate evidence or vulnerabilities.
2. If evidence is insufficient, state 'Insufficient evidence.'
3. Return valid JSON adhering to this structure:
{
  "executive_summary": "string",
  "risk_narrative": "string",
  "remediation_roadmap": [
    { "priority": 1, "title": "string", "action": "string", "target": "string" }
  ]
}

Sanitized Findings Data:
${JSON.stringify(sanitizedSummary, null, 2)}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${config.geminiApiKey}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' },
      }),
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    const parsed = JSON.parse(text);

    return {
      provider: this.name,
      executive_summary: parsed.executive_summary || 'Analysis complete.',
      risk_narrative: parsed.risk_narrative || 'Evaluation finished.',
      remediation_roadmap: Array.isArray(parsed.remediation_roadmap) ? parsed.remediation_roadmap : [],
    };
  }
}
