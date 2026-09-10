import { AIProvider } from './providers/providerInterface.js';
import { HeuristicAIProvider } from './providers/heuristicProvider.js';
import { GeminiAIProvider } from './providers/geminiProvider.js';
import { OpenAIProvider } from './providers/openaiProvider.js';
import { Finding, ScanRecord, AIAnalysis } from '../types/index.js';
import { config } from '../config.js';

class AIService {
  private defaultProvider: AIProvider = new HeuristicAIProvider();

  async analyze(scan: ScanRecord, findings: Finding[]): Promise<AIAnalysis> {
    // If Gemini key is provided, prefer Gemini
    if (config.geminiApiKey) {
      try {
        const gemini = new GeminiAIProvider();
        return await gemini.analyze(scan, findings);
      } catch (err: any) {
        console.warn(`[AI Service] Gemini analysis failed (${err.message}). Falling back to heuristic provider.`);
      }
    }

    // If OpenAI key is provided, try OpenAI
    if (config.openaiApiKey) {
      try {
        const openai = new OpenAIProvider();
        return await openai.analyze(scan, findings);
      } catch (err: any) {
        console.warn(`[AI Service] OpenAI analysis failed (${err.message}). Falling back to heuristic provider.`);
      }
    }

    // Default expert heuristic provider
    return await this.defaultProvider.analyze(scan, findings);
  }
}

export const aiService = new AIService();
