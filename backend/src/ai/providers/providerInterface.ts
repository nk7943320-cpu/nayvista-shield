import { Finding, ScanRecord, AIAnalysis } from '../../types/index.js';

export interface AIProvider {
  name: string;
  analyze(scan: ScanRecord, findings: Finding[]): Promise<AIAnalysis>;
}
