import React, {useState, useEffect} from 'react';
import {
    LineChart,
    Line,
    PieChart,
    Pie,
    Cell,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer
} from 'recharts';
import {AlertTriangle, Shield, Activity, Lock, Unlock, Ban, CheckCircle} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

// Define interfaces
interface Stats {
    total_packets: number;
    threats_detected: number;
    packets_blocked: number;
    packets_prevented: number;
    normal_traffic: number;
    detection_rate: number;
    prevention_rate: number;
    nips_active_blocks: number;
    nips_total_blocks: number;
}

interface Alert {
    id: number;
    alert_type: string;
    severity: string;
    source_ip: string;
    dest_ip: string;
    timestamp: string;
    protocol: string;
    dest_port?: number;
    blocked: boolean;
    prevention_action?: string;
}

interface DisplayAlert {
    id: number;
    type: string;
    severity: string;
    source: string;
    destination: string;
    time: string;
    protocol: string;
    port: number;
    blocked: boolean;
    prevention_action?: string;
}

interface TrafficDataPoint {
    time: string;
    packets: number;
    threats: number;
    prevented: number;
}

interface ThreatType {
    name: string;
    value: number;
}

const NIPSDashboard = () => {
    const [stats, setStats] = useState<Stats>({
        total_packets: 0,
        threats_detected: 0,
        packets_blocked: 0,
        packets_prevented: 0,
        normal_traffic: 0,
        detection_rate: 0,
        prevention_rate: 0,
        nips_active_blocks: 0,
        nips_total_blocks: 0
    });

    const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
    const [whitelist, setWhitelist] = useState<string[]>([]);
    const [trafficData, setTrafficData] = useState<TrafficDataPoint[]>([]);
    const [threatTypes, setThreatTypes] = useState<any[]>([]);
    const [recentAlerts, setRecentAlerts] = useState<DisplayAlert[]>([]);
    const [autoBlock, setAutoBlock] = useState(true);
    const [ipInput, setIpInput] = useState('');

    useEffect(() => {
        const interval = setInterval(fetchData, 2000);
        fetchData();
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statsRes, alertsRes, nipsRes] = await Promise.all([
                fetch(`${API_BASE}/stats`),
                fetch(`${API_BASE}/alerts?limit=50`),
                fetch(`${API_BASE}/nips/blocked-ips`)
            ]);

            const realStats: Stats = await statsRes.json();
            const realAlerts: Alert[] = await alertsRes.json();
            const nipsData = await nipsRes.json();

            setStats(realStats);
            setBlockedIPs(nipsData.blocked_ips || []);
            setWhitelist(nipsData.whitelist || []);

            const displayAlerts: DisplayAlert[] = realAlerts.map((a: Alert) => ({
                id: a.id,
                type: a.alert_type,
                severity: a.severity,
                source: a.source_ip,
                destination: a.dest_ip,
                time: new Date(a.timestamp).toLocaleTimeString('en-US', {hour12: false}),
                protocol: a.protocol,
                port: a.dest_port || 0,
                blocked: a.blocked,
                prevention_action: a.prevention_action
            }));
            setRecentAlerts(displayAlerts);

            const now = new Date().toLocaleTimeString('en-US', {hour12: false});
            setTrafficData(prev => [...prev, {
                time: now,
                packets: realStats.total_packets,
                threats: realStats.threats_detected,
                prevented: realStats.packets_prevented
            }].slice(-20));

            const threatCount = realAlerts.reduce((acc: Record<string, number>, a: Alert) => {
                acc[a.alert_type] = (acc[a.alert_type] || 0) + 1;
                return acc;
            }, {});

            setThreatTypes(Object.entries(threatCount).map(([name, value]) => ({name, value})));

        } catch (err) {
            console.error('Error fetching data:', err);
        }
    };

    const handleWhitelist = async () => {
        try {
            await fetch(`${API_BASE}/nips/whitelist`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ipInput, action: 'whitelist'})
            });
            setIpInput('');
            fetchData();
        } catch (err) {
            console.error('Error whitelisting IP:', err);
        }
    };

    const handleBlacklist = async () => {
        try {
            await fetch(`${API_BASE}/nips/blacklist`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip: ipInput, action: 'blacklist'})
            });
            setIpInput('');
            fetchData();
        } catch (err) {
            console.error('Error blacklisting IP:', err);
        }
    };

    const handleUnblock = async (ip: string) => {
        try {
            await fetch(`${API_BASE}/nips/unblock`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip, action: 'unblock'})
            });
            fetchData();
        } catch (err) {
            console.error('Error unblocking IP:', err);
        }
    };

    const toggleAutoBlock = async () => {
        try {
            await fetch(`${API_BASE}/nips/config/auto-block?enabled=${!autoBlock}`, {
                method: 'POST'
            });
            setAutoBlock(!autoBlock);
        } catch (err) {
            console.error('Error toggling auto-block:', err);
        }
    };

    const COLORS = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899'];

    const getSeverityColor = (severity: string): string => {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'bg-red-500/20 text-red-400 border border-red-600/40';
            case 'high':
                return 'bg-orange-500/20 text-orange-400 border border-orange-600/40';
            case 'medium':
                return 'bg-yellow-500/20 text-yellow-400 border border-yellow-600/40';
            default:
                return 'bg-blue-500/20 text-blue-400 border border-blue-600/40';
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900 text-white p-6">
            <div className="max-w-7xl mx-auto space-y-6">

                {/* Header */}
                <div className="flex justify-between items-center">
                    <div className="flex items-center gap-4">
                        <Shield className="w-12 h-12 text-cyan-400"/>
                        <div>
                            <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                                NIDS + NIPS
                            </h1>
                            <p className="text-slate-400">Detection + Active Prevention</p>
                        </div>
                    </div>
                    <button
                        onClick={toggleAutoBlock}
                        className={`flex items-center gap-2 px-6 py-3 rounded-lg font-bold transition-all ${
                            autoBlock
                                ? 'bg-green-600 hover:bg-green-700 text-white'
                                : 'bg-red-600 hover:bg-red-700 text-white'
                        }`}
                    >
                        {autoBlock ? <Lock className="w-5 h-5"/> : <Unlock className="w-5 h-5"/>}
                        {autoBlock ? 'Auto-Block: ON' : 'Auto-Block: OFF'}
                    </button>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    {[
                        {
                            icon: Activity,
                            label: "Packets",
                            value: stats.total_packets.toLocaleString(),
                            color: "text-cyan-400"
                        },
                        {icon: AlertTriangle, label: "Threats", value: stats.threats_detected, color: "text-red-400"},
                        {
                            icon: Shield,
                            label: "Prevented",
                            value: stats.packets_prevented,
                            color: "text-green-400",
                            extra: `${stats.prevention_rate}%`
                        },
                        {icon: Lock, label: "Active Blocks", value: stats.nips_active_blocks, color: "text-orange-400"},
                        {icon: Ban, label: "Total Blocks", value: stats.nips_total_blocks, color: "text-purple-400"},
                    ].map((stat, i) => (
                        <div key={i}
                             className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-4 hover:border-purple-500/50 transition-all">
                            <div className="flex items-center gap-2 mb-2">
                                <stat.icon className={`w-6 h-6 ${stat.color}`}/>
                                <h3 className="text-sm font-semibold text-slate-300">{stat.label}</h3>
                            </div>
                            <p className="text-3xl font-bold">{stat.value}</p>
                            {stat.extra && <p className="text-xs text-slate-400 mt-1">{stat.extra}</p>}
                        </div>
                    ))}
                </div>

                {/* IP Management */}
                <div className="grid lg:grid-cols-2 gap-6">
                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                            <Ban className="w-6 h-6 text-red-400"/>
                            Blocked IPs ({blockedIPs.length})
                        </h2>
                        <div className="space-y-2 max-h-60 overflow-y-auto">
                            {blockedIPs.length === 0 ? (
                                <p className="text-slate-500 text-center py-8">No IPs currently blocked</p>
                            ) : (
                                blockedIPs.map(ip => (
                                    <div key={ip}
                                         className="flex items-center justify-between bg-slate-900/50 p-3 rounded-lg">
                                        <span className="font-mono text-red-400">{ip}</span>
                                        <button
                                            onClick={() => handleUnblock(ip)}
                                            className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-sm font-semibold"
                                        >
                                            Unblock
                                        </button>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                            <CheckCircle className="w-6 h-6 text-green-400"/>
                            Whitelist ({whitelist.length})
                        </h2>
                        <div className="space-y-4">
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={ipInput}
                                    onChange={(e) => setIpInput(e.target.value)}
                                    placeholder="Enter IP address..."
                                    className="flex-1 bg-slate-900 border border-slate-600 rounded px-4 py-2 text-white focus:outline-none focus:border-cyan-400"
                                />
                                <button
                                    onClick={handleWhitelist}
                                    className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded font-semibold"
                                >
                                    Whitelist
                                </button>
                                <button
                                    onClick={handleBlacklist}
                                    className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded font-semibold"
                                >
                                    Blacklist
                                </button>
                            </div>
                            <div className="space-y-2 max-h-40 overflow-y-auto">
                                {whitelist.map(ip => (
                                    <div key={ip} className="bg-slate-900/50 p-2 rounded">
                                        <span className="font-mono text-green-400">{ip}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Charts */}
                <div className="grid lg:grid-cols-2 gap-6">
                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 text-cyan-400">Traffic & Prevention</h2>
                        <ResponsiveContainer width="100%" height={280}>
                            <LineChart data={trafficData}>
                                <CartesianGrid strokeDasharray="4 4" stroke="#334155"/>
                                <XAxis dataKey="time" stroke="#94a3b8"/>
                                <YAxis stroke="#94a3b8"/>
                                <Tooltip
                                    contentStyle={{backgroundColor: '#1e293b', border: 'none', borderRadius: '8px'}}/>
                                <Legend/>
                                <Line type="monotone" dataKey="packets" stroke="#06b6d4" strokeWidth={3} name="Total"/>
                                <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={3}
                                      name="Threats"/>
                                <Line type="monotone" dataKey="prevented" stroke="#10b981" strokeWidth={3}
                                      name="Prevented"/>
                            </LineChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 text-purple-400">Threat Types</h2>
                        <ResponsiveContainer width="100%" height={280}>
                            <PieChart>
                                <Pie
                                    data={threatTypes as any}
                                    cx="50%"
                                    cy="50%"
                                    outerRadius={80}
                                    fill="#8884d8"
                                    dataKey="value"
                                    label={(props: any) => {
                                        const {name, value, percent} = props;
                                        if (!percent) return null;
                                        return `${name} ${Math.round(percent * 100)}%`;
                                    }}
                                >
                                    {threatTypes.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]}/>
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{backgroundColor: '#1e293b', border: 'none', borderRadius: '8px'}}/>
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Alerts Table */}
                <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-xl p-6">
                    <h2 className="text-xl font-bold mb-4 text-red-400">Latest Alerts</h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                            <tr className="text-slate-400 border-b border-slate-700">
                                <th className="text-left py-3 px-4">Time</th>
                                <th className="text-left py-3 px-4">Type</th>
                                <th className="text-left py-3 px-4">Severity</th>
                                <th className="text-left py-3 px-4">Source</th>
                                <th className="text-left py-3 px-4">Status</th>
                                <th className="text-left py-3 px-4">Action</th>
                            </tr>
                            </thead>
                            <tbody>
                            {recentAlerts.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="text-center py-12 text-slate-500">
                                        No threats detected - System secure
                                    </td>
                                </tr>
                            ) : (
                                recentAlerts.slice(0, 10).map(alert => (
                                    <tr key={alert.id}
                                        className="border-b border-slate-700/50 hover:bg-slate-700/40 transition">
                                        <td className="py-3 px-4 font-mono text-sm">{alert.time}</td>
                                        <td className="py-3 px-4 font-bold text-red-400">{alert.type}</td>
                                        <td className="py-3 px-4">
                                                <span
                                                    className={`${getSeverityColor(alert.severity)} px-3 py-1 rounded-full text-xs font-bold`}>
                                                    {alert.severity}
                                                </span>
                                        </td>
                                        <td className="py-3 px-4 font-mono text-cyan-300">{alert.source}</td>
                                        <td className="py-3 px-4">
                                            {alert.blocked ? (
                                                <span className="flex items-center gap-1 text-green-400">
                                                        <Lock className="w-4 h-4"/>
                                                        <span className="font-semibold">BLOCKED</span>
                                                    </span>
                                            ) : (
                                                <span className="text-yellow-400 font-semibold">DETECTED</span>
                                            )}
                                        </td>
                                        <td className="py-3 px-4 text-xs text-slate-400">{alert.prevention_action}</td>
                                    </tr>
                                ))
                            )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NIPSDashboard;