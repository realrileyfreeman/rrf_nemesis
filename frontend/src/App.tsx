import React, { useState } from 'react';
import axios from 'axios';
import { Shield, Search, Server, AlertTriangle, ShieldAlert, Zap, Globe, FileKey, Activity, Code, FolderOpen, Printer, Wand2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface Port { port: number; banner: string }
interface Vuln { type: string; url: string }
interface Tech { category: string; name: string; source: string }
interface Path { url: string; status: number }

interface ScanResult {
  target: string;
  scan_time: string;
  open_ports: Port[];
  web_vulnerabilities: Vuln[];
  security_headers: Record<string, string>;
  discovered_paths: Path[];
  technologies: Tech[];
}

interface SastResult {
  results: {
    check_id: string;
    path: string;
    start: { line: number };
    extra: {
      message: string;
      severity: string;
    }
  }[];
}

function App() {
  const [activeTab, setActiveTab] = useState<'DAST' | 'SAST'>('DAST');

  // DAST State
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanningDast, setIsScanningDast] = useState(false);
  const [dastResults, setDastResults] = useState<ScanResult | null>(null);
  
  // SAST State
  const [targetPath, setTargetPath] = useState('');
  const [isScanningSast, setIsScanningSast] = useState(false);
  const [sastResults, setSastResults] = useState<SastResult | null>(null);

  // AI State
  const [aiRemediation, setAiRemediation] = useState<string | null>(null);
  const [isThinking, setIsThinking] = useState(false);

  const [error, setError] = useState('');

  const handleDastScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    setIsScanningDast(true); setError(''); setDastResults(null);
    try {
      const response = await axios.post('http://localhost:8001/scan', { target: targetUrl });
      setDastResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "An error occurred during DAST scan.");
    } finally {
      setIsScanningDast(false);
    }
  };

  const handleSastScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath) return;
    setIsScanningSast(true); setError(''); setSastResults(null);
    try {
      const response = await axios.post('http://localhost:8001/sast', { path: targetPath });
      if (response.data.error) throw new Error(response.data.error);
      setSastResults(response.data);
    } catch (err: any) {
      setError(err.message || err.response?.data?.detail || "An error occurred during SAST scan.");
    } finally {
      setIsScanningSast(false);
    }
  };

  const handleAiFix = async (type: string, message: string) => {
    setIsThinking(true);
    setAiRemediation(null);
    try {
      const response = await axios.post('http://localhost:8001/remediate', {
        vulnerability_type: type,
        issue_text: message
      });
      setAiRemediation(response.data.remediation_code);
    } catch (err) {
      setAiRemediation("Failed to contact Nemesis AI Engine.");
    } finally {
      setIsThinking(false);
    }
  };

  const getMissingHeadersCount = () => {
    if (!dastResults) return 0;
    return Object.values(dastResults.security_headers).filter(v => v === 'MISSING').length;
  };

  const getChartData = () => {
    if (!dastResults) return [];
    return [
      { name: 'Ports', count: dastResults.open_ports.length, fill: '#3fb950' },
      { name: 'Vulns', count: dastResults.web_vulnerabilities.length, fill: '#f85149' },
      { name: 'Paths', count: dastResults.discovered_paths.length, fill: '#d29922' },
      { name: 'Techs', count: dastResults.technologies.length, fill: '#58a6ff' },
    ];
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev.toUpperCase();
    if (s.includes('ERROR') || s.includes('HIGH')) return 'badge-danger';
    if (s.includes('WARNING') || s.includes('MEDIUM')) return 'badge-warning';
    return 'badge-success';
  };

  const getDastSummary = () => {
    if (!dastResults) return "";
    const vulns = dastResults.web_vulnerabilities.length;
    const paths = dastResults.discovered_paths.length;
    let text = `The dynamic audit identified ${vulns} critical web vulnerability(ies) and ${dastResults.open_ports.length} open port(s). `;
    if (vulns > 0 || getMissingHeadersCount() > 2) {
      text += "The overall security posture of the application is CRITICAL. Immediate remediation is required on exposed endpoints.";
    } else if (paths > 5) {
      text += "The security posture is MODERATE. Multiple paths are exposed, increasing the attack surface.";
    } else {
      text += "The security posture is SATISFACTORY. No major vulnerabilities were detected.";
    }
    return text;
  };

  const getSastSummary = () => {
    if (!sastResults) return "";
    const total = sastResults.results.length;
    const errors = sastResults.results.filter(r => r.extra.severity.toUpperCase().includes('ERROR')).length;
    let text = `The static code analysis (Semgrep) identified ${total} total flaw(s), including ${errors} of HIGH severity. `;
    if (errors > 0) {
      text += "The source code requires an URGENT review of secure development practices, particularly to address highlighted critical flaws.";
    } else if (total > 0) {
      text += "The code contains minor flaws (Warnings). A code review is recommended to improve robustness.";
    } else {
      text += "No vulnerabilities were detected. The code follows good security practices.";
    }
    return text;
  };

  return (
    <div className="min-h-screen flex flex-col items-center py-10 px-4 md:px-10 lg:px-20 print:p-0 print:bg-white print:text-black">
      
      {/* Header */}
      <div className="flex items-center gap-4 mb-8 print:mb-4">
        <ShieldAlert size={48} className="text-cyber-primary print:text-blue-800" />
        <div>
          <h1 className="text-4xl font-bold tracking-widest text-white print:text-black">NEMESIS</h1>
          <p className="text-cyber-muted uppercase tracking-wider text-sm mt-1 print:text-gray-600">Executive Security Audit Report</p>
        </div>
      </div>

      {/* Tabs - Hidden on Print */}
      <div className="flex bg-cyber-card rounded-lg p-1 mb-10 w-full max-w-sm print:hidden">
        <button 
          onClick={() => {setActiveTab('DAST'); setError('')}}
          className={`flex-1 py-2 text-sm font-bold uppercase tracking-wider rounded-md transition-all flex items-center justify-center gap-2 ${activeTab === 'DAST' ? 'bg-cyber-primary text-white shadow' : 'text-cyber-muted hover:text-white'}`}
        >
          <Globe size={16} /> Web Scan (DAST)
        </button>
        <button 
          onClick={() => {setActiveTab('SAST'); setError('')}}
          className={`flex-1 py-2 text-sm font-bold uppercase tracking-wider rounded-md transition-all flex items-center justify-center gap-2 ${activeTab === 'SAST' ? 'bg-cyber-primary text-white shadow' : 'text-cyber-muted hover:text-white'}`}
        >
          <Code size={16} /> Code Scan (SAST)
        </button>
      </div>

      {/* Search Bar - Hidden on Print */}
      {activeTab === 'DAST' ? (
        <form onSubmit={handleDastScan} className="w-full max-w-2xl mb-12 relative animate-fade-in print:hidden">
          <div className="relative flex items-center">
            <Globe className="absolute left-4 text-cyber-muted" size={20} />
            <input 
              type="text" placeholder="https://example.com"
              className="w-full bg-cyber-card border-2 border-cyber-border rounded-full py-4 pl-12 pr-32 text-white focus:outline-none focus:border-cyber-primary transition-colors"
              value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} disabled={isScanningDast}
            />
            <button type="submit" disabled={isScanningDast || !targetUrl} className="absolute right-2 bg-cyber-primary hover:bg-blue-600 text-white font-bold py-2 px-6 rounded-full transition-colors flex items-center gap-2 disabled:opacity-50">
              {isScanningDast ? <Activity className="animate-spin" size={20} /> : <Search size={20} />}
              SCAN
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleSastScan} className="w-full max-w-2xl mb-12 relative animate-fade-in print:hidden">
          <div className="relative flex items-center">
            <FolderOpen className="absolute left-4 text-cyber-muted" size={20} />
            <input 
              type="text" placeholder="/path/to/source/code"
              className="w-full bg-cyber-card border-2 border-cyber-border rounded-full py-4 pl-12 pr-32 text-white focus:outline-none focus:border-cyber-primary transition-colors font-mono text-sm"
              value={targetPath} onChange={(e) => setTargetPath(e.target.value)} disabled={isScanningSast}
            />
            <button type="submit" disabled={isScanningSast || !targetPath} className="absolute right-2 bg-cyber-primary hover:bg-blue-600 text-white font-bold py-2 px-6 rounded-full transition-colors flex items-center gap-2 disabled:opacity-50">
              {isScanningSast ? <Activity className="animate-spin" size={20} /> : <Search size={20} />}
              ANALYZE
            </button>
          </div>
        </form>
      )}

      {error && <p className="text-cyber-danger mb-4 text-center print:hidden">{error}</p>}

      {/* Loading State - Hidden on Print */}
      {(isScanningDast || isScanningSast) && (
        <div className="flex flex-col items-center mt-10 print:hidden">
          <div className="relative w-32 h-32">
            <div className="absolute inset-0 rounded-full border-t-2 border-b-2 border-cyber-primary animate-spin"></div>
            <div className="absolute inset-2 rounded-full border-l-2 border-r-2 border-cyber-danger animate-spin-reverse"></div>
            <div className="absolute inset-0 flex items-center justify-center">
              <Shield size={32} className="text-cyber-muted animate-pulse" />
            </div>
          </div>
          <p className="text-cyber-primary mt-6 tracking-widest uppercase animate-pulse">Running full audit...</p>
        </div>
      )}

      {/* DAST Results Dashboard */}
      {activeTab === 'DAST' && dastResults && !isScanningDast && (
        <div className="w-full max-w-6xl animate-fade-in">
          
          <div className="mb-6 pb-2 border-b border-cyber-border print:border-gray-300 flex justify-between items-end">
            <h2 className="text-2xl font-bold text-white print:text-black">Dynamic Web Scan Results</h2>
            <div className="flex items-center gap-4">
              <button onClick={() => window.print()} className="print:hidden flex items-center gap-2 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] text-white px-4 py-1 rounded transition-colors text-sm">
                <Printer size={16} /> Export PDF
              </button>
              <span className="text-cyber-muted print:text-gray-600 font-mono text-sm">Target: <span className="text-cyber-primary print:text-blue-600">{dastResults.target}</span></span>
            </div>
          </div>

          <div className="mb-8 p-4 bg-cyber-card border-l-4 border-cyber-primary rounded print:border-l-4 print:border-blue-600 print:bg-gray-50 print:text-black">
            <h3 className="text-sm font-bold uppercase tracking-wider text-cyber-primary mb-2 print:text-blue-600">Executive Summary</h3>
            <p className="text-gray-300 text-sm leading-relaxed print:text-gray-700">{getDastSummary()}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8 print:grid-cols-4">
            <div className="card flex items-center gap-4 print:border-gray-300 print:shadow-none print:bg-gray-50">
              <div className="p-4 rounded-full bg-[#1f4b2e] text-cyber-success print:bg-green-100 print:text-green-800"><Server size={28} /></div>
              <div><p className="text-3xl font-bold text-white print:text-black">{dastResults.open_ports.length}</p><p className="text-xs text-cyber-muted uppercase font-bold tracking-wider print:text-gray-600">Open Ports</p></div>
            </div>
            <div className="card flex items-center gap-4 print:border-gray-300 print:shadow-none print:bg-gray-50">
              <div className="p-4 rounded-full bg-[#3d1c1c] text-cyber-danger print:bg-red-100 print:text-red-800"><AlertTriangle size={28} /></div>
              <div><p className="text-3xl font-bold text-white print:text-black">{dastResults.web_vulnerabilities.length}</p><p className="text-xs text-cyber-muted uppercase font-bold tracking-wider print:text-gray-600">Vulnerabilities</p></div>
            </div>
            <div className="card flex items-center gap-4 print:border-gray-300 print:shadow-none print:bg-gray-50">
              <div className="p-4 rounded-full bg-[#3d2e00] text-cyber-warning print:bg-yellow-100 print:text-yellow-800"><Shield size={28} /></div>
              <div><p className="text-3xl font-bold text-white print:text-black">{getMissingHeadersCount()}</p><p className="text-xs text-cyber-muted uppercase font-bold tracking-wider print:text-gray-600">Missing Headers</p></div>
            </div>
            <div className="card flex items-center gap-4 print:border-gray-300 print:shadow-none print:bg-gray-50">
              <div className="p-4 rounded-full bg-blue-900/30 text-cyber-primary print:bg-blue-100 print:text-blue-800"><FileKey size={28} /></div>
              <div><p className="text-3xl font-bold text-white print:text-black">{dastResults.discovered_paths.length}</p><p className="text-xs text-cyber-muted uppercase font-bold tracking-wider print:text-gray-600">Exposed Paths</p></div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8 print:grid-cols-2 print:gap-4">
            <div className="card print:border-gray-300 print:shadow-none print:bg-white print:break-inside-avoid">
              <h3 className="text-cyber-muted uppercase tracking-wider text-sm font-bold mb-6 border-b border-cyber-border print:border-gray-300 print:text-gray-800 pb-2 flex items-center gap-2"><BarChart size={16} /> Findings Distribution</h3>
              <div className="h-64 w-full print:h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={getChartData()} margin={{ top: 5, right: 30, left: -20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                    <XAxis dataKey="name" stroke="#8b949e" />
                    <YAxis stroke="#8b949e" allowDecimals={false} />
                    <Tooltip cursor={{fill: '#21262d'}} contentStyle={{backgroundColor: '#161b22', borderColor: '#30363d', color: '#fff'}} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="card flex flex-col h-full max-h-96 print:max-h-none print:border-gray-300 print:shadow-none print:bg-white print:break-inside-avoid">
              <h3 className="text-cyber-muted uppercase tracking-wider text-sm font-bold mb-4 border-b border-cyber-border print:border-gray-300 print:text-gray-800 pb-2 flex items-center gap-2"><AlertTriangle size={16} /> Web Vulnerabilities</h3>
              <div className="overflow-y-auto pr-2 print:overflow-visible">
                {dastResults.web_vulnerabilities.length === 0 ? (
                  <p className="text-center text-cyber-muted py-8 print:text-gray-500">No vulnerabilities found.</p>
                ) : (
                  <table className="w-full text-left text-sm print:text-black">
                    <thead><tr className="text-cyber-muted print:text-gray-600 border-b border-cyber-border print:border-gray-300"><th className="py-2">Type</th><th className="py-2">Endpoint URL</th><th className="py-2 print:hidden">Action</th></tr></thead>
                    <tbody>
                      {dastResults.web_vulnerabilities.map((v, i) => (
                        <tr key={i} className="border-b border-cyber-border/50 print:border-gray-200">
                          <td className="py-3"><span className="badge badge-danger print:text-red-700 print:bg-transparent print:p-0">{v.type}</span></td>
                          <td className="py-3 font-mono text-xs text-cyber-primary print:text-blue-700 break-all">{v.url}</td>
                          <td className="py-3 print:hidden">
                            <button onClick={() => handleAiFix(v.type, v.url)} className="flex items-center gap-1 text-xs bg-purple-900/50 hover:bg-purple-800 text-purple-300 px-2 py-1 rounded">
                              <Wand2 size={12} /> Auto-Fix
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8 print:grid-cols-2 print:gap-4">
            {/* Open Ports */}
            <div className="card max-h-80 flex flex-col print:border-gray-300 print:shadow-none print:bg-white print:break-inside-avoid">
              <h3 className="text-cyber-muted uppercase tracking-wider text-sm font-bold mb-4 border-b border-cyber-border print:border-gray-300 print:text-gray-800 pb-2 flex items-center gap-2">
                <Server size={16} /> Open Ports
              </h3>
              <div className="overflow-y-auto pr-2 print:overflow-visible">
                {dastResults.open_ports.length === 0 ? (
                  <p className="text-center text-cyber-muted py-8 print:text-gray-500">No open ports found.</p>
                ) : (
                  <table className="w-full text-left text-sm print:text-black">
                    <thead>
                      <tr className="text-cyber-muted border-b border-cyber-border print:border-gray-300">
                        <th className="py-2">Port</th>
                        <th className="py-2">Banner</th>
                        <th className="py-2 print:hidden">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dastResults.open_ports.map((p, i) => (
                        <tr key={i} className="border-b border-cyber-border/50 print:border-gray-200">
                          <td className="py-3 w-16"><span className="badge badge-success print:bg-transparent print:text-green-700 print:p-0">{p.port}</span></td>
                          <td className="py-3 font-mono text-xs truncate max-w-[150px]">{p.banner || "Unknown"}</td>
                          <td className="py-3 print:hidden">
                            <button onClick={() => handleAiFix("port", p.port.toString())} className="flex items-center gap-1 text-xs bg-purple-900/50 hover:bg-purple-800 text-purple-300 px-2 py-1 rounded">
                              <Wand2 size={12} /> Auto-Fix
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Technologies */}
            <div className="card lg:col-span-2 max-h-80 flex flex-col print:border-gray-300 print:shadow-none print:bg-white print:break-inside-avoid">
              <h3 className="text-cyber-muted uppercase tracking-wider text-sm font-bold mb-4 border-b border-cyber-border print:border-gray-300 print:text-gray-800 pb-2 flex items-center gap-2">
                <Zap size={16} /> Stack Fingerprinting
              </h3>
              <div className="overflow-y-auto pr-2 print:overflow-visible">
                {dastResults.technologies.length === 0 ? (
                  <p className="text-center text-cyber-muted py-8 print:text-gray-500">No technologies detected.</p>
                ) : (
                  <table className="w-full text-left text-sm print:text-black">
                    <thead>
                      <tr className="text-cyber-muted border-b border-cyber-border print:border-gray-300">
                        <th className="py-2">Category</th>
                        <th className="py-2">Technology</th>
                        <th className="py-2">Detection Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dastResults.technologies.map((t, i) => (
                        <tr key={i} className="border-b border-cyber-border/50 print:border-gray-200">
                          <td className="py-3"><span className="badge badge-warning print:bg-transparent print:text-yellow-700 print:p-0">{t.category}</span></td>
                          <td className="py-3 font-bold">{t.name}</td>
                          <td className="py-3 font-mono text-xs text-cyber-muted print:text-gray-500">{t.source}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </div>
      )}


      {/* SAST Results Dashboard */}
      {activeTab === 'SAST' && sastResults && !isScanningSast && (
        <div className="w-full max-w-6xl animate-fade-in">
          <div className="mb-6 pb-2 border-b border-cyber-border print:border-gray-300 flex justify-between items-end">
            <h2 className="text-2xl font-bold text-white print:text-black">Static Code Analysis (Semgrep)</h2>
            <div className="flex items-center gap-4">
              <button onClick={() => window.print()} className="print:hidden flex items-center gap-2 bg-[#161b22] hover:bg-[#21262d] border border-[#30363d] text-white px-4 py-1 rounded transition-colors text-sm">
                <Printer size={16} /> Export PDF
              </button>
              <span className="text-cyber-muted font-mono text-sm print:text-gray-600">Total Vulnerabilities: <span className="text-cyber-primary print:text-blue-600">{sastResults.results.length}</span></span>
            </div>
          </div>

          <div className="mb-8 p-4 bg-cyber-card border-l-4 border-cyber-primary rounded print:border-l-4 print:border-blue-600 print:bg-gray-50 print:text-black">
            <h3 className="text-sm font-bold uppercase tracking-wider text-cyber-primary mb-2 print:text-blue-600">Executive Summary</h3>
            <p className="text-gray-300 text-sm leading-relaxed print:text-gray-700">{getSastSummary()}</p>
          </div>

          <div className="card print:border-gray-300 print:shadow-none print:bg-white print:text-black">
            <h3 className="text-cyber-muted uppercase tracking-wider text-sm font-bold mb-4 border-b border-cyber-border print:border-gray-300 print:text-gray-800 pb-2 flex items-center gap-2">
              <Code size={16} /> Code Vulnerabilities
            </h3>
            {sastResults.results.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-cyber-success print:text-green-700">
                <Shield size={32} className="mb-2 opacity-50" />
                <p>No code vulnerabilities found! Your code is secure.</p>
              </div>
            ) : (
              <div className="overflow-x-auto print:overflow-visible">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="text-cyber-muted print:text-gray-600 border-b border-cyber-border print:border-gray-300">
                      <th className="py-2">Severity</th>
                      <th className="py-2">File</th>
                      <th className="py-2">Line</th>
                      <th className="py-2">Description</th>
                      <th className="py-2 print:hidden">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sastResults.results.map((res, i) => (
                      <tr key={i} className="border-b border-cyber-border/50 print:border-gray-200 hover:bg-cyber-card/80 transition-colors">
                        <td className="py-3"><span className={`badge ${getSeverityBadge(res.extra.severity)} print:bg-transparent print:p-0 ${getSeverityBadge(res.extra.severity).replace('badge-', 'text-')}-600`}>{res.extra.severity}</span></td>
                        <td className="py-3 font-mono text-xs text-cyber-primary print:text-blue-700">{res.path.split('/').pop()}</td>
                        <td className="py-3 font-mono text-xs">{res.start.line}</td>
                        <td className="py-3 text-xs text-gray-300 print:text-gray-700">
                          <strong>{res.check_id.split('.').pop()}</strong>: {res.extra.message.substring(0, 80)}...
                        </td>
                        <td className="py-3 print:hidden">
                          <button onClick={() => handleAiFix(res.check_id, res.extra.message)} className="flex items-center gap-1 text-xs bg-purple-900/50 hover:bg-purple-800 text-purple-300 px-2 py-1 rounded">
                            <Wand2 size={12} /> Auto-Fix
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* AI Remediation Modal */}
      {(isThinking || aiRemediation) && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 print:hidden animate-fade-in p-4">
          <div className="bg-cyber-card border border-purple-500/50 shadow-[0_0_30px_rgba(168,85,247,0.2)] rounded-lg w-full max-w-3xl overflow-hidden">
            <div className="bg-purple-900/40 p-4 border-b border-purple-500/30 flex justify-between items-center">
              <h3 className="text-lg font-bold text-purple-300 flex items-center gap-2"><Wand2 size={20} /> Nemesis AI Engine</h3>
              <button onClick={() => {setAiRemediation(null); setIsThinking(false);}} className="text-gray-400 hover:text-white">✕</button>
            </div>
            <div className="p-6 min-h-[200px]">
              {isThinking ? (
                <div className="flex flex-col items-center justify-center h-full gap-4 text-purple-400">
                  <Activity size={40} className="animate-spin" />
                  <p className="tracking-widest uppercase text-sm animate-pulse">Analyzing Vulnerability Context...</p>
                </div>
              ) : (
                <div className="text-gray-200">
                  <p className="mb-4 text-sm text-purple-300 italic">Analysis complete. Below is the recommended fix.</p>
                  <pre className="bg-[#0d1117] border border-[#30363d] rounded p-4 overflow-x-auto text-sm font-mono whitespace-pre-wrap">
                    {aiRemediation}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin-reverse { from { transform: rotate(360deg); } to { transform: rotate(0deg); } }
        .animate-spin-reverse { animation: spin-reverse 2s linear infinite; }
        @keyframes fade-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .animate-fade-in { animation: fade-in 0.3s ease-out forwards; }
        @media print {
          @page { margin: 1cm; }
          body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background-color: white !important; }
          .badge { border: 1px solid currentColor; }
        }
      `}</style>

    </div>
  );
}

export default App;
