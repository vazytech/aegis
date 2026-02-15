
import { GoogleGenAI, Type } from "@google/genai";
import { Severity } from "../types";

// Fix: Initialized GoogleGenAI with named parameters as per strict guidelines.
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeVulnerability = async (params: {
  targetUrl: string;
  payload: string;
  statusCode: number;
  responseSnippet: string;
}) => {
  const { targetUrl, payload, statusCode, responseSnippet } = params;

  // Fix: Switched to 'gemini-3-pro-preview' for advanced security reasoning/audit tasks.
  const response = await ai.models.generateContent({
    model: "gemini-3-pro-preview",
    contents: `Analyze the following security scan result:
Target: ${targetUrl}
Payload: ${payload}
Status Code: ${statusCode}
Response Snippet: ${responseSnippet}`,
    config: {
      systemInstruction: `You are an expert Senior Penetration Tester and Secure Code Auditor. 
Your task is to analyze the raw HTTP response data provided from an automated security scan.

INSTRUCTIONS:
1. ANALYSIS: Determine if the payload successfully triggered a vulnerability. Look for SQL syntax errors, reflected inputs, or abnormal behavior.
2. SEVERITY: Assign a severity level (Critical, High, Medium, Low).
3. EXPLANATION: Explain briefly *why* this is a vulnerability in simple terms.
4. REMEDIATION: Provide specific code fixes. Use Markdown code blocks.

OUTPUT FORMAT:
Return response in JSON format with keys: "vulnerability_found" (boolean), "severity" (string), "analysis" (string), "fix_suggestion" (string).`,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          vulnerability_found: { type: Type.BOOLEAN },
          severity: { type: Type.STRING },
          analysis: { type: Type.STRING },
          fix_suggestion: { type: Type.STRING },
        },
        required: ["vulnerability_found", "severity", "analysis", "fix_suggestion"],
      },
    },
  });

  // Fix: Accessed extracted string output via .text property as required by guidelines and handled potentially undefined text.
  const jsonStr = response.text?.trim() || '{}';
  return JSON.parse(jsonStr);
};
