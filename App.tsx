
import React, { useState, useCallback, useEffect, useRef } from 'react';
import { 
  Shield, 
  Terminal, 
  Activity, 
  AlertCircle, 
  Database, 
  Layout, 
  Zap, 
  Lock,
  ChevronRight,
  RefreshCw,
  Bell,
  Cpu,
  Github,
  Search,
  Bug,
  X,
  User,
  Settings,
  LogOut,
  FileText,
  Clock,
  ExternalLink,
  Copy,
  CheckCircle
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts';
import { ScanResult, Severity, ScanStatus } from './types';
import { VULN_TYPES, NAV_ITEMS } from './constants';
import { analyzeVulnerability } from './services/geminiService';
import { runRealScan, checkBackendHealth } from './services/scannerApi';

const MOCK_SCAN_DATA = [
  { time: '00:00', count: 2 },
  { time: '04:00', count: 5 },
  { time: '08:00', count: 12 },
  { time: '12:00', count: 8 },
  { time: '16:00', count: 15 },
  { time: '20:00', count: 10 },
  { time: '23:59', count: 3 },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [targetUrl, setTargetUrl] = useState('');
  const [selectedVuln, setSelectedVuln] = useState(VULN_TYPES[0]);
  const [scanStatus, setScanStatus] = useState<ScanStatus>(ScanStatus.IDLE);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [notifications, setNotifications] = useState<{msg: string, time: Date}[]>([]);
  const [backendOnline, setBackendOnline] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [reportFilter, setReportFilter] = useState<'all' | 'critical'>('all');
  const [selectedReport, setSelectedReport] = useState<ScanResult | null>(null);
  const notificationRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const addNotification = (msg: string) => {
    setNotifications(prev => [{msg, time: new Date()}, ...prev].slice(0, 10));
  };

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setShowProfile(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Check backend health on mount
  useEffect(() => {
    const checkBackend = async () => {
      const isOnline = await checkBackendHealth();
      setBackendOnline(isOnline);
      if (!isOnline) {
        addNotification('⚠️ Backend offline - Start with: npm run server');
      } else {
        addNotification('✅ Scanner backend connected');
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 10000);
    return () => clearInterval(interval);
  }, []);

  const runScan = async () => {
    if (!targetUrl) return;
    
    // Check backend first
    if (!backendOnline) {
      addNotification('❌ Cannot scan: Backend is offline. Run: npm run server');
      return;
    }
    
    setScanStatus(ScanStatus.SCANNING);
    addNotification(`🔍 Initiating REAL ${selectedVuln.name} scan on ${targetUrl}`);

    try {
      // Run REAL scan against target
      const scanResult = await runRealScan({
        targetUrl,
        vulnType: selectedVuln.name,
        payload: selectedVuln.defaultPayload
      });

      setScanStatus(ScanStatus.ANALYZING);
      addNotification(`🧠 Analyzing results with Gemini AI...`);

      // Use Gemini for additional AI analysis if vulnerability found
      let aiAnalysis = scanResult.analysis;
      let aiFix = scanResult.fix_suggestion;

      if (scanResult.vulnerability_found && scanResult.rawResponses.length > 0) {
        try {
          const aiResponse = await analyzeVulnerability({
            targetUrl,
            payload: scanResult.findings[0]?.payload || selectedVuln.defaultPayload,
            statusCode: scanResult.rawResponses[0]?.statusCode || 200,
            responseSnippet: scanResult.rawResponses[0]?.snippet || ''
          });
          
          // Combine scanner findings with AI analysis
          aiAnalysis = `${scanResult.analysis}\n\n--- AI ANALYSIS ---\n${aiResponse.analysis}`;
          aiFix = `${scanResult.fix_suggestion}\n\n--- AI RECOMMENDATIONS ---\n${aiResponse.fix_suggestion}`;
        } catch (aiError) {
          console.log('AI analysis failed, using scanner results:', aiError);
        }
      }

      const newResult: ScanResult = {
        id: Math.random().toString(36).substring(7),
        timestamp: new Date().toLocaleTimeString(),
        targetUrl,
        payload: scanResult.findings[0]?.payload || selectedVuln.defaultPayload,
        vulnType: selectedVuln.name,
        vulnerability_found: scanResult.vulnerability_found,
        severity: (scanResult.severity as Severity) || Severity.LOW,
        analysis: aiAnalysis,
        fix_suggestion: aiFix,
        rawResponse: {
          statusCode: scanResult.rawResponses[0]?.statusCode || 0,
          snippet: scanResult.rawResponses[0]?.snippet || 'No response captured'
        }
      };

      setResults(prev => [newResult, ...prev]);
      setScanStatus(ScanStatus.COMPLETED);
      
      if (newResult.vulnerability_found) {
        addNotification(`🚨 CRITICAL: ${newResult.vulnType} vulnerability discovered!`);
      } else {
        addNotification(`✅ Scan complete: No vulnerabilities detected.`);
      }

    } catch (error) {
      console.error(error);
      setScanStatus(ScanStatus.FAILED);
      addNotification(`❌ Error: ${error instanceof Error ? error.message : 'Scan failed'}`);
    }
  };

  return (
    <div className="flex min-h-screen bg-[#0a0a0c] text-gray-200">
      {/* Sidebar */}
      <aside className="w-64 border-r border-gray-800 bg-[#0d0d10] flex flex-col fixed inset-y-0 z-50 transition-all duration-300">
        <div className="p-6 flex items-center gap-3">
          <div className="w-10 h-10 bg-indigo-600 rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(79,70,229,0.3)]">
            <Shield className="text-white" size={24} />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-tight text-white">AEGIS AI</h1>
            <p className="text-[10px] text-indigo-400 font-bold uppercase tracking-widest">Pentest Agent</p>
          </div>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 ${
                activeTab === item.id 
                  ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-600/20' 
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`}
            >
              {item.icon}
              <span className="font-medium text-sm">{item.label}</span>
              {activeTab === item.id && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-500 shadow-[0_0_8px_#6366f1]" />}
            </button>
          ))}
        </nav>

        <div className="p-6 border-t border-gray-800">
          <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-800">
            <div className="flex items-center gap-2 mb-2">
              <Cpu size={14} className={backendOnline ? "text-green-500" : "text-red-500"} />
              <span className="text-[11px] font-bold text-gray-500 uppercase">Scanner Status</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-300">Backend Server</span>
              <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                backendOnline 
                  ? 'bg-green-500/10 text-green-500 border-green-500/20' 
                  : 'bg-red-500/10 text-red-500 border-red-500/20'
              }`}>
                {backendOnline ? 'Online' : 'Offline'}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 flex-1 flex flex-col">
        {/* Top Header */}
        <header className="h-16 border-b border-gray-800 bg-[#0d0d10]/80 backdrop-blur-md flex items-center justify-between px-8 sticky top-0 z-40">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-widest">Workspace /</span>
            <span className="text-xs font-bold text-white uppercase tracking-widest">{activeTab}</span>
          </div>
          <div className="flex items-center gap-6">
            {/* Notifications Dropdown */}
            <div className="relative" ref={notificationRef}>
              <button 
                onClick={() => setShowNotifications(!showNotifications)}
                className="relative p-2 hover:bg-white/5 rounded-lg transition-colors"
              >
                <Bell size={20} className="text-gray-400 hover:text-white transition-colors" />
                {notifications.length > 0 && (
                  <span className="absolute top-1 right-1 w-2 h-2 bg-indigo-500 rounded-full animate-pulse" />
                )}
              </button>
              
              {showNotifications && (
                <div className="absolute right-0 mt-2 w-80 bg-[#0d0d10] border border-gray-800 rounded-2xl shadow-2xl overflow-hidden z-50">
                  <div className="p-4 border-b border-gray-800 flex items-center justify-between">
                    <h3 className="font-bold text-sm">Notifications</h3>
                    <button 
                      onClick={() => setNotifications([])}
                      className="text-xs text-gray-500 hover:text-white transition-colors"
                    >
                      Clear all
                    </button>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="p-8 text-center">
                        <Bell className="mx-auto text-gray-700 mb-2" size={24} />
                        <p className="text-gray-600 text-xs">No notifications</p>
                      </div>
                    ) : (
                      notifications.map((note, idx) => (
                        <div key={idx} className="p-4 border-b border-gray-800/50 hover:bg-white/5 transition-colors">
                          <p className="text-sm text-gray-300">{note.msg}</p>
                          <p className="text-[10px] text-gray-600 mt-1">
                            {note.time.toLocaleTimeString()}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Profile Dropdown */}
            <div className="relative" ref={profileRef}>
              <button 
                onClick={() => setShowProfile(!showProfile)}
                className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-600 to-purple-600 p-0.5 hover:scale-105 transition-transform"
              >
                <div className="w-full h-full rounded-full bg-[#0d0d10] flex items-center justify-center overflow-hidden">
                  <User size={16} className="text-gray-400" />
                </div>
              </button>

              {showProfile && (
                <div className="absolute right-0 mt-2 w-56 bg-[#0d0d10] border border-gray-800 rounded-2xl shadow-2xl overflow-hidden z-50">
                  <div className="p-4 border-b border-gray-800">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-indigo-600 to-purple-600 p-0.5">
                        <div className="w-full h-full rounded-full bg-[#0d0d10] flex items-center justify-center">
                          <User size={20} className="text-gray-400" />
                        </div>
                      </div>
                      <div>
                        <p className="font-bold text-sm text-white">Security Admin</p>
                        <p className="text-xs text-gray-500">admin@aegis.ai</p>
                      </div>
                    </div>
                  </div>
                  <div className="p-2">
                    <button 
                      onClick={() => { setActiveTab('settings'); setShowProfile(false); }}
                      className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-white/5 hover:text-white transition-colors"
                    >
                      <Settings size={16} />
                      Settings
                    </button>
                    <button className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:bg-white/5 hover:text-white transition-colors">
                      <FileText size={16} />
                      Documentation
                    </button>
                    <div className="border-t border-gray-800 my-2" />
                    <button className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-red-400 hover:bg-red-500/10 transition-colors">
                      <LogOut size={16} />
                      Sign out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto w-full space-y-8">
          {activeTab === 'dashboard' && (
            <div className="space-y-8 animate-in fade-in duration-500">
              <div className="flex items-end justify-between">
                <div>
                  <h2 className="text-3xl font-bold text-white tracking-tight">Security Overview</h2>
                  <p className="text-gray-400 mt-1">Real-time heuristics and vulnerability telemetry.</p>
                </div>
                <div className="flex gap-3">
                  <button className="flex items-center gap-2 bg-white/5 hover:bg-white/10 px-4 py-2 rounded-lg text-sm border border-white/10 transition-all">
                    <RefreshCw size={16} />
                    Refresh
                  </button>
                  <button 
                    onClick={() => setActiveTab('scanner')}
                    className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded-lg text-sm font-medium shadow-[0_0_15px_rgba(79,70,229,0.3)] transition-all"
                  >
                    New Scan
                  </button>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {(() => {
                  const criticalCount = results.filter(r => 
                    r.severity === Severity.CRITICAL || r.severity === 'Critical'
                  ).length;
                  const highCount = results.filter(r => 
                    r.severity === Severity.HIGH || r.severity === 'High'
                  ).length;
                  const vulnerableCount = results.filter(r => r.vulnerability_found).length;
                  const totalScans = results.length;
                  
                  // Calculate security score based on scan results
                  const securityScore = totalScans === 0 
                    ? 100 
                    : Math.max(0, Math.round(100 - ((criticalCount * 25) + (highCount * 15) + ((vulnerableCount - criticalCount - highCount) * 5))));
                  
                  return [
                    { label: 'Total Scans', value: totalScans, icon: <Search size={20} />, color: 'text-indigo-500' },
                    { label: 'Critical Vulns', value: criticalCount, icon: <AlertCircle size={20} />, color: 'text-red-500' },
                    { label: 'High Severity', value: highCount, icon: <Shield size={20} />, color: 'text-orange-500' },
                    { label: 'Security Score', value: `${securityScore}%`, icon: <Zap size={20} />, color: securityScore >= 80 ? 'text-green-500' : securityScore >= 50 ? 'text-yellow-500' : 'text-red-500' },
                  ];
                })().map((stat, i) => (
                  <div key={i} className="bg-[#0d0d10] border border-gray-800 p-6 rounded-2xl hover:border-gray-700 transition-colors group">
                    <div className="flex items-start justify-between mb-4">
                      <div className={`p-2 rounded-lg bg-gray-900 border border-gray-800 ${stat.color} group-hover:scale-110 transition-transform`}>
                        {stat.icon}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-gray-500 text-xs font-bold uppercase tracking-wider">{stat.label}</h4>
                      <p className="text-3xl font-bold text-white mt-1">{stat.value}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Activity Chart */}
                <div className="lg:col-span-2 bg-[#0d0d10] border border-gray-800 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-8">
                    <h3 className="font-bold text-lg flex items-center gap-2">
                      <Activity size={18} className="text-indigo-500" />
                      Scan Velocity
                    </h3>
                  </div>
                  <div className="h-[300px] w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={MOCK_SCAN_DATA}>
                        <defs>
                          <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                        <XAxis dataKey="time" stroke="#4b5563" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis stroke="#4b5563" fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#0d0d10', border: '1px solid #1f2937', borderRadius: '8px' }}
                          itemStyle={{ color: '#6366f1' }}
                        />
                        <Area type="monotone" dataKey="count" stroke="#6366f1" fillOpacity={1} fill="url(#colorCount)" strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Notifications Feed */}
                <div className="bg-[#0d0d10] border border-gray-800 rounded-2xl p-6 flex flex-col">
                  <h3 className="font-bold text-lg mb-6 flex items-center gap-2">
                    <Terminal size={18} className="text-indigo-500" />
                    Live Terminal
                  </h3>
                  <div className="flex-1 space-y-4 overflow-y-auto max-h-[300px] mono">
                    {notifications.length === 0 && (
                      <p className="text-gray-600 text-xs text-center py-10 italic">Awaiting telemetry...</p>
                    )}
                    {notifications.map((note, idx) => (
                      <div key={idx} className="text-xs flex gap-2 border-l border-gray-800 pl-3">
                        <span className="text-indigo-500 font-bold">[{note.time.toLocaleTimeString()}]</span>
                        <span className="text-gray-400">{note.msg}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Recent Findings */}
              <div className="bg-[#0d0d10] border border-gray-800 rounded-2xl overflow-hidden">
                <div className="p-6 border-b border-gray-800 flex items-center justify-between">
                  <h3 className="font-bold text-lg">Recent Findings</h3>
                  <button onClick={() => setActiveTab('reports')} className="text-indigo-400 text-xs font-bold hover:underline">VIEW ALL REPORTS</button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-gray-500 text-[10px] font-bold uppercase tracking-widest bg-gray-900/50">
                        <th className="px-6 py-4">Status</th>
                        <th className="px-6 py-4">Severity</th>
                        <th className="px-6 py-4">Target</th>
                        <th className="px-6 py-4">Vulnerability</th>
                        <th className="px-6 py-4">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {results.slice(0, 5).map((result) => (
                        <tr key={result.id} className="hover:bg-white/5 transition-colors cursor-pointer group">
                          <td className="px-6 py-4">
                            {result.vulnerability_found ? (
                              <span className="flex items-center gap-1.5 text-red-500 text-xs font-bold">
                                <AlertCircle size={14} /> VULNERABLE
                              </span>
                            ) : (
                              <span className="flex items-center gap-1.5 text-green-500 text-xs font-bold">
                                <Shield size={14} /> SECURE
                              </span>
                            )}
                          </td>
                          <td className="px-6 py-4">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              result.severity === Severity.CRITICAL ? 'bg-red-500/10 text-red-500 border-red-500/20' :
                              result.severity === Severity.HIGH ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' :
                              'bg-indigo-500/10 text-indigo-500 border-indigo-500/20'
                            }`}>
                              {result.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm text-gray-300 truncate max-w-[200px] mono">
                            {result.targetUrl}
                          </td>
                          <td className="px-6 py-4 text-sm font-medium text-white">
                            {result.vulnType}
                          </td>
                          <td className="px-6 py-4 text-xs text-gray-500">
                            {result.timestamp}
                          </td>
                        </tr>
                      ))}
                      {results.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-6 py-12 text-center text-gray-600 italic">No scan history found. Start your first scan.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'scanner' && (
            <div className="max-w-4xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
              <div className="text-center">
                <h2 className="text-3xl font-bold text-white mb-2">Initialize Security Audit</h2>
                <p className="text-gray-400">Deploy the AI Pentest Agent to evaluate target security postures.</p>
              </div>

              <div className="bg-[#0d0d10] border border-gray-800 rounded-3xl p-8 shadow-2xl">
                <div className="space-y-6">
                  <div>
                    <label className="block text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Target Endpoint URL</label>
                    <div className="relative">
                      <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                      <input 
                        type="text" 
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="https://example.com/api/v1"
                        className="w-full bg-gray-900 border border-gray-700 rounded-xl py-4 pl-12 pr-4 text-white focus:outline-none focus:border-indigo-500 transition-colors"
                      />
                    </div>
                    <p className="text-[10px] text-red-500 mt-2 font-medium tracking-tight uppercase">⚠️ Ensure you have explicit permission to test this target.</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {VULN_TYPES.map((type) => (
                      <button
                        key={type.id}
                        onClick={() => setSelectedVuln(type)}
                        className={`text-left p-4 rounded-xl border transition-all ${
                          selectedVuln.id === type.id 
                            ? 'bg-indigo-600/10 border-indigo-600 shadow-[0_0_15px_rgba(79,70,229,0.2)]' 
                            : 'bg-gray-900 border-gray-800 hover:border-gray-700'
                        }`}
                      >
                        <div className="flex items-center gap-3 mb-1">
                          <Bug size={16} className={selectedVuln.id === type.id ? 'text-indigo-400' : 'text-gray-500'} />
                          <h4 className="font-bold text-sm">{type.name}</h4>
                        </div>
                        <p className="text-xs text-gray-500 leading-relaxed">{type.description}</p>
                      </button>
                    ))}
                  </div>

                  <div className="pt-4">
                    <button 
                      onClick={runScan}
                      disabled={!targetUrl || scanStatus === ScanStatus.SCANNING || scanStatus === ScanStatus.ANALYZING}
                      className={`w-full py-4 rounded-xl font-bold flex items-center justify-center gap-3 shadow-lg transition-all ${
                        !targetUrl || scanStatus !== ScanStatus.IDLE && scanStatus !== ScanStatus.COMPLETED && scanStatus !== ScanStatus.FAILED
                        ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                        : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_20px_rgba(79,70,229,0.4)] hover:scale-[1.01]'
                      }`}
                    >
                      {(scanStatus === ScanStatus.SCANNING || scanStatus === ScanStatus.ANALYZING) ? (
                        <>
                          <RefreshCw className="animate-spin" size={20} />
                          {scanStatus === ScanStatus.SCANNING ? 'ENGAGING SCANNER...' : 'AI BRAIN ANALYZING...'}
                        </>
                      ) : (
                        <>
                          <Search size={20} />
                          INITIATE PENETRATION TEST
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Latest Result Card */}
              {results.length > 0 && scanStatus === ScanStatus.COMPLETED && (
                <div className="bg-[#0d0d10] border border-gray-800 rounded-3xl overflow-hidden shadow-2xl animate-in fade-in zoom-in duration-500">
                  <div className={`px-8 py-4 flex items-center justify-between ${
                    results[0].vulnerability_found ? 'bg-red-500/10' : 'bg-green-500/10'
                  }`}>
                    <div className="flex items-center gap-3">
                      {results[0].vulnerability_found ? <AlertCircle className="text-red-500" /> : <Shield className="text-green-500" />}
                      <span className={`text-sm font-bold tracking-widest uppercase ${
                        results[0].vulnerability_found ? 'text-red-500' : 'text-green-500'
                      }`}>
                        Scan Verdict: {results[0].vulnerability_found ? 'VULNERABILITY DETECTED' : 'SYSTEM SECURE'}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 font-bold uppercase mono">ID: {results[0].id}</span>
                  </div>

                  <div className="p-8 space-y-8">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      <div className="space-y-4">
                        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest">Analysis Details</h4>
                        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
                          <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-line">
                            {results[0].analysis}
                          </p>
                        </div>
                      </div>

                      <div className="space-y-4">
                        <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest">Remediation Guide</h4>
                        <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800 h-full">
                           <pre className="text-xs text-indigo-300 mono overflow-x-auto whitespace-pre-wrap">
                            {results[0].fix_suggestion}
                           </pre>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest">Network Telemetry (Raw Snippet)</h4>
                      <div className="bg-black/40 rounded-xl p-4 border border-gray-800 mono text-xs text-gray-500 overflow-x-auto">
                        <p className="mb-2 text-indigo-400 font-bold uppercase tracking-widest">HTTP RESPONSE {results[0].rawResponse?.statusCode}</p>
                        {results[0].rawResponse?.snippet}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'reports' && !selectedReport && (
             <div className="space-y-6 animate-in fade-in duration-500">
              <div className="flex items-center justify-between">
                <h2 className="text-3xl font-bold text-white">Audit History</h2>
                <div className="bg-gray-900 border border-gray-800 rounded-lg p-1 flex">
                  <button 
                    onClick={() => setReportFilter('all')}
                    className={`px-4 py-1.5 text-xs font-bold rounded-md transition-colors ${
                      reportFilter === 'all' ? 'bg-indigo-600 text-white' : 'text-gray-500 hover:text-white'
                    }`}
                  >
                    All Logs
                  </button>
                  <button 
                    onClick={() => setReportFilter('critical')}
                    className={`px-4 py-1.5 text-xs font-bold rounded-md transition-colors ${
                      reportFilter === 'critical' ? 'bg-red-600 text-white' : 'text-gray-500 hover:text-white'
                    }`}
                  >
                    Critical ({results.filter(r => r.severity === Severity.CRITICAL || r.severity === Severity.HIGH || r.severity === 'Critical' || r.severity === 'High').length})
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                {(() => {
                  const filteredResults = reportFilter === 'critical' 
                    ? results.filter(r => r.severity === Severity.CRITICAL || r.severity === Severity.HIGH || r.severity === 'Critical' || r.severity === 'High')
                    : results;
                  
                  if (filteredResults.length === 0) {
                    return (
                      <div className="py-32 text-center bg-[#0d0d10] border border-gray-800 rounded-3xl">
                        <Database className="mx-auto text-gray-700 mb-4" size={48} />
                        <h3 className="text-xl font-bold text-gray-500">
                          {reportFilter === 'critical' ? 'No Critical Findings' : 'Archive Empty'}
                        </h3>
                        <p className="text-gray-600 mt-2">
                          {reportFilter === 'critical' 
                            ? 'No critical or high severity vulnerabilities found.' 
                            : 'Historical scan data will be persisted here.'}
                        </p>
                      </div>
                    );
                  }
                  
                  return filteredResults.map((result) => (
                    <div 
                      key={result.id} 
                      onClick={() => setSelectedReport(result)}
                      className="bg-[#0d0d10] border border-gray-800 p-6 rounded-2xl hover:border-indigo-600/50 transition-all cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-6 group"
                    >
                      <div className="flex items-center gap-4">
                        <div className={`p-3 rounded-xl ${result.vulnerability_found ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}`}>
                          {result.vulnerability_found ? <AlertCircle size={24} /> : <Shield size={24} />}
                        </div>
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-bold text-lg group-hover:text-indigo-400 transition-colors">{result.vulnType} Scan</h4>
                            <span className={`text-[10px] font-black px-2 py-0.5 rounded-full ${
                              result.severity === Severity.CRITICAL ? 'bg-red-500/20 text-red-500' :
                              result.severity === Severity.HIGH ? 'bg-orange-500/20 text-orange-500' :
                              result.severity === Severity.MEDIUM ? 'bg-yellow-500/20 text-yellow-500' :
                              'bg-indigo-500/20 text-indigo-400'
                            }`}>
                              {result.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-500 mono">{result.targetUrl}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-6">
                        <div className="text-right hidden md:block">
                          <p className="text-xs text-gray-500 font-bold uppercase tracking-widest">Timestamp</p>
                          <p className="text-sm text-white font-medium">{result.timestamp}</p>
                        </div>
                        <div className="bg-white/5 group-hover:bg-indigo-600/20 p-3 rounded-xl border border-white/10 group-hover:border-indigo-600/30 transition-colors">
                          <ChevronRight size={20} className="text-gray-400 group-hover:text-indigo-400 transition-colors" />
                        </div>
                      </div>
                    </div>
                  ));
                })()}
              </div>
             </div>
          )}

          {/* Full Report View */}
          {activeTab === 'reports' && selectedReport && (
            <div className="space-y-6 animate-in fade-in duration-300">
              {/* Back button and header */}
              <div className="flex items-center justify-between">
                <button 
                  onClick={() => setSelectedReport(null)}
                  className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                >
                  <ChevronRight size={20} className="rotate-180" />
                  <span className="text-sm font-medium">Back to Reports</span>
                </button>
                <div className="flex gap-2">
                  <button 
                    onClick={() => navigator.clipboard.writeText(JSON.stringify(selectedReport, null, 2))}
                    className="flex items-center gap-2 bg-white/5 hover:bg-white/10 px-4 py-2 rounded-lg text-sm border border-white/10 transition-all"
                  >
                    <Copy size={16} />
                    Copy JSON
                  </button>
                </div>
              </div>

              {/* Report Header */}
              <div className={`rounded-3xl overflow-hidden border ${
                selectedReport.vulnerability_found ? 'border-red-500/30' : 'border-green-500/30'
              }`}>
                <div className={`px-8 py-6 flex items-center justify-between ${
                  selectedReport.vulnerability_found ? 'bg-red-500/10' : 'bg-green-500/10'
                }`}>
                  <div className="flex items-center gap-4">
                    {selectedReport.vulnerability_found ? (
                      <AlertCircle className="text-red-500" size={32} />
                    ) : (
                      <CheckCircle className="text-green-500" size={32} />
                    )}
                    <div>
                      <h2 className="text-2xl font-bold text-white">{selectedReport.vulnType}</h2>
                      <p className={`text-sm font-bold uppercase tracking-widest ${
                        selectedReport.vulnerability_found ? 'text-red-400' : 'text-green-400'
                      }`}>
                        {selectedReport.vulnerability_found ? 'VULNERABILITY DETECTED' : 'SYSTEM SECURE'}
                      </p>
                    </div>
                  </div>
                  <span className={`text-sm font-black px-4 py-2 rounded-full ${
                    selectedReport.severity === Severity.CRITICAL ? 'bg-red-500/20 text-red-500 border border-red-500/30' :
                    selectedReport.severity === Severity.HIGH ? 'bg-orange-500/20 text-orange-500 border border-orange-500/30' :
                    selectedReport.severity === Severity.MEDIUM ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/30' :
                    'bg-green-500/20 text-green-400 border border-green-500/30'
                  }`}>
                    {selectedReport.severity.toUpperCase()}
                  </span>
                </div>

                <div className="bg-[#0d0d10] p-8 space-y-8">
                  {/* Meta Info */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-800">
                      <p className="text-xs text-gray-500 font-bold uppercase tracking-widest mb-1">Target URL</p>
                      <p className="text-sm text-white mono break-all">{selectedReport.targetUrl}</p>
                    </div>
                    <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-800">
                      <p className="text-xs text-gray-500 font-bold uppercase tracking-widest mb-1">Timestamp</p>
                      <p className="text-sm text-white flex items-center gap-2">
                        <Clock size={14} className="text-gray-500" />
                        {selectedReport.timestamp}
                      </p>
                    </div>
                    <div className="bg-gray-900/50 rounded-xl p-4 border border-gray-800">
                      <p className="text-xs text-gray-500 font-bold uppercase tracking-widest mb-1">Report ID</p>
                      <p className="text-sm text-indigo-400 mono">{selectedReport.id}</p>
                    </div>
                  </div>

                  {/* Payload Used */}
                  <div>
                    <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Payload Tested</h4>
                    <div className="bg-black/40 rounded-xl p-4 border border-gray-800 mono text-sm text-orange-400 overflow-x-auto">
                      {selectedReport.payload}
                    </div>
                  </div>

                  {/* Analysis */}
                  <div>
                    <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Analysis Details</h4>
                    <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
                      <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-line">
                        {selectedReport.analysis}
                      </p>
                    </div>
                  </div>

                  {/* Remediation */}
                  <div>
                    <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Remediation Guide</h4>
                    <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
                      <pre className="text-xs text-indigo-300 mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {selectedReport.fix_suggestion}
                      </pre>
                    </div>
                  </div>

                  {/* Raw Response */}
                  <div>
                    <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">HTTP Response Data</h4>
                    <div className="bg-black/40 rounded-xl p-4 border border-gray-800 mono text-xs overflow-x-auto">
                      <div className="flex items-center gap-2 mb-3">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${
                          selectedReport.rawResponse?.statusCode && selectedReport.rawResponse.statusCode >= 200 && selectedReport.rawResponse.statusCode < 300
                            ? 'bg-green-500/20 text-green-400'
                            : selectedReport.rawResponse?.statusCode && selectedReport.rawResponse.statusCode >= 400
                            ? 'bg-red-500/20 text-red-400'
                            : 'bg-yellow-500/20 text-yellow-400'
                        }`}>
                          HTTP {selectedReport.rawResponse?.statusCode || 'N/A'}
                        </span>
                        <span className="text-gray-600">Response Snippet</span>
                      </div>
                      <div className="text-gray-500 whitespace-pre-wrap break-all">
                        {selectedReport.rawResponse?.snippet || 'No response data captured'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="max-w-2xl mx-auto space-y-12 animate-in fade-in duration-500">
               <div className="text-center">
                <h2 className="text-3xl font-bold text-white mb-2">Agent Configuration</h2>
                <p className="text-gray-400">Manage API keys, alerting webhooks, and core logic parameters.</p>
              </div>

              <div className="space-y-6">
                 <div className="bg-[#0d0d10] border border-gray-800 rounded-3xl p-8 space-y-6">
                    <h3 className="font-bold text-lg border-b border-gray-800 pb-4">Webhook Integration</h3>
                    <div>
                      <label className="block text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Discord Webhook URL</label>
                      <input 
                        type="password" 
                        value="****************************************************"
                        readOnly
                        className="w-full bg-gray-900 border border-gray-700 rounded-xl py-3 px-4 text-gray-500 focus:outline-none"
                      />
                      <p className="text-[10px] text-gray-600 mt-2">A notification will be dispatched whenever a HIGH or CRITICAL vulnerability is confirmed.</p>
                    </div>
                 </div>

                 <div className="bg-[#0d0d10] border border-gray-800 rounded-3xl p-8 space-y-6">
                    <h3 className="font-bold text-lg border-b border-gray-800 pb-4">AI Model Preferences</h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="bg-indigo-600/10 border border-indigo-600/30 p-4 rounded-xl">
                           <div className="flex items-center gap-2 mb-2">
                             <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
                             <span className="text-xs font-bold">gemini-3-flash-preview</span>
                           </div>
                           <p className="text-[10px] text-gray-500">Balanced speed and reasoning for rapid audit analysis.</p>
                        </div>
                        <div className="bg-gray-900 border border-gray-800 p-4 rounded-xl opacity-50 cursor-not-allowed">
                           <div className="flex items-center gap-2 mb-2">
                             <div className="w-2 h-2 rounded-full bg-gray-600" />
                             <span className="text-xs font-bold">gemini-3-pro-preview</span>
                           </div>
                           <p className="text-[10px] text-gray-500">Deep reasoning for complex secure code review tasks.</p>
                        </div>
                    </div>
                 </div>

                 <div className="flex justify-end pt-6">
                    <button className="bg-indigo-600 hover:bg-indigo-500 px-8 py-3 rounded-xl font-bold transition-all shadow-lg text-sm">Save Global Settings</button>
                 </div>
              </div>

              <div className="pt-20 pb-10 flex flex-col items-center gap-4 text-gray-600">
                <div className="flex items-center gap-4">
                  <Github size={20} className="hover:text-white cursor-pointer transition-colors" />
                  <Layout size={20} className="hover:text-white cursor-pointer transition-colors" />
                </div>
                <p className="text-[10px] font-bold uppercase tracking-widest">Built for Security Leaders & Pentest Enthusiasts</p>
                <p className="text-[9px] text-gray-700">© 2024 AEGIS AI SECURITY. AUTHORIZED TESTING ONLY.</p>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
