import React, {useState, useEffect} from 'react';
import {
    LineChart, Line, PieChart, Pie, Cell,
    XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import {AlertTriangle, Shield, Activity, Clock} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

interface Alert {
    id: number;
    timestamp: string;
    alert_type: string;
    severity: string;
    source_ip: string;
    dest_ip: string;
    source_port?: number;
    dest_port?: number;
    protocol: string;
    description: string;
    confidence: number;
    blocked: boolean;
}

interface Stats {
    total_packets: number;
    threats_detected: number;
    packets_blocked: number;
    normal_traffic: number;
    detection_rate: number;
    uptime_seconds: number;
}

const NIDSDashboard = () => {
    const [stats, setStats] = useState<Stats>({
        total_packets: 0,
        threats_detected: 0,
        packets_blocked: 0,
        normal_traffic: 0,
        detection_rate: 0,
        uptime_seconds: 0
    });

    const [trafficData, setTrafficData] = useState<Array<{
        time: string;
        packets: number;
        threats: number;
        normal: number
    }>>([]);
    const [threatTypes, setThreatTypes] = useState<Array<{ name: string; value: number }>>([]);
    const [recentAlerts, setRecentAlerts] = useState<Array<{
        id: number;
        type: string;
        severity: string;
        source: string;
        destination: string;
        time: string;
        protocol: string;
        port: number;
    }>>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const interval = setInterval(fetchData, 2000);
        fetchData(); // First load immediately
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statsRes, alertsRes] = await Promise.all([
                fetch(`${API_BASE}/stats`),
                fetch(`${API_BASE}/alerts?limit=50`)
            ]);

            if (!statsRes.ok || !alertsRes.ok) throw new Error('API error');

            const realStats: Stats = await statsRes.json();
            const realAlerts: Alert[] = await alertsRes.json();

            setStats(realStats);

            const displayAlerts = realAlerts.map(a => ({
                id: a.id,
                type: a.alert_type,
                severity: a.severity,
                source: a.source_ip,
                destination: a.dest_ip,
                time: new Date(a.timestamp).toLocaleTimeString('en-US', {hour12: false}),
                protocol: a.protocol,
                port: a.dest_port || 0
            }));
            setRecentAlerts(displayAlerts);

            const now = new Date().toLocaleTimeString('en-US', {hour12: false});
            setTrafficData(prev => [...prev, {
                time: now,
                packets: realStats.total_packets,
                threats: realStats.threats_detected,
                normal: realStats.normal_traffic
            }].slice(-20));

            const threatCount = realAlerts.reduce((acc: Record<string, number>, a) => {
                acc[a.alert_type] = (acc[a.alert_type] || 0) + 1;
                return acc;
            }, {});
            setThreatTypes(Object.entries(threatCount).map(([name, value]) => ({name, value})));

            setError(null);
        } catch (err: any) {
            setError('Backend offline or error: ' + err.message);
        }
    };

    const COLORS = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899'];

    const getSeverityColor = (severity: string) => {
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
            <div className="max-w-7xl mx-auto space-y-8">

                {/* Header */}
                <div className="flex justify-between items-center">
                    <div className="flex items-center gap-4">
                        <Shield className="w-10 h-10 text-cyan-400"/>
                        <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                            REAL-TIME NIDS — LIVE IN TUNISIA
                        </h1>
                    </div>
                    <div className="flex items-center gap-3 text-green-400 font-bold text-xl animate-pulse">
                        <div className="w-4 h-4 bg-green-400 rounded-full animate-ping"/>
                        LIVE & ARMED
                    </div>
                </div>

                {error && (
                    <div className="bg-red-900/50 border border-red-500 rounded-xl p-4 text-red-300 font-mono">
                        {error}
                    </div>
                )}

                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                    {[
                        {
                            icon: Activity,
                            label: "Total Packets",
                            value: stats.total_packets.toLocaleString(),
                            color: "text-cyan-400"
                        },
                        {
                            icon: AlertTriangle,
                            label: "Threats Detected",
                            value: stats.threats_detected,
                            color: "text-red-400",
                            extra: `${stats.detection_rate.toFixed(3)}%`
                        },
                        {icon: Shield, label: "Packets Blocked", value: stats.packets_blocked, color: "text-green-400"},
                        {
                            icon: Clock,
                            label: "Uptime",
                            value: `${Math.floor(stats.uptime_seconds / 60)}m ${stats.uptime_seconds % 60}s`,
                            color: "text-purple-400"
                        },
                    ].map((stat, i) => (
                        <div key={i}
                             className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-2xl p-6 hover:border-purple-500/50 transition-all">
                            <div className="flex items-center gap-3 mb-3">
                                <stat.icon className={`w-7 h-7 ${stat.color}`}/>
                                <h3 className="text-lg font-semibold text-slate-300">{stat.label}</h3>
                            </div>
                            <p className="text-4xl font-bold">{stat.value}</p>
                            {stat.extra && <p className="text-sm text-slate-400 mt-1">{stat.extra}</p>}
                        </div>
                    ))}
                </div>

                {/* Charts */}
                <div className="grid lg:grid-cols-2 gap-8">
                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-2xl p-6">
                        <h2 className="text-2xl font-bold mb-4 text-cyan-400">Live Traffic Flow</h2>
                        <ResponsiveContainer width="100%" height={320}>
                            <LineChart data={trafficData}>
                                <CartesianGrid strokeDasharray="4 4" stroke="#334155"/>
                                <XAxis dataKey="time" stroke="#94a3b8"/>
                                <YAxis stroke="#94a3b8"/>
                                <Tooltip
                                    contentStyle={{backgroundColor: '#1e293b', border: 'none', borderRadius: '8px'}}/>
                                <Legend/>
                                <Line type="monotone" dataKey="packets" stroke="#06b6d4" strokeWidth={3} dot={false}
                                      name="Total"/>
                                <Line type="monotone" dataKey="normal" stroke="#10b981" strokeWidth={3} dot={false}
                                      name="Normal"/>
                                <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={3} dot={false}
                                      name="Threats"/>
                            </LineChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-2xl p-6">
                        <h2 className="text-2xl font-bold mb-4 text-purple-400">Threat Distribution</h2>
                        <ResponsiveContainer width="100%" height={320}>
                            <PieChart>
                                <Pie
                                    data={threatTypes}
                                    cx="50%"
                                    cy="50%"
                                    labelLine={false}
                                    outerRadius={80}
                                    fill="#8884d8"
                                    dataKey="value"
                                    label={(props: any) => {
                                        const {name, value} = props;
                                        const total = threatTypes.reduce((sum, item) => sum + item.value, 0);
                                        const percent = total === 0 ? 0 : Math.round((value / total) * 100);
                                        return `${name} ${percent}%`;
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
                <div className="bg-slate-800/60 backdrop-blur border border-slate-700 rounded-2xl p-6">
                    <h2 className="text-2xl font-bold mb-4 text-red-400">Latest Alerts</h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                            <tr className="text-slate-400 border-b border-slate-700">
                                <th className="text-left py-3 px-4">Time</th>
                                <th className="text-left py-3 px-4">Attack Type</th>
                                <th className="text-left py-3 px-4">Severity</th>
                                <th className="text-left py-3 px-4">Source IP</th>
                                <th className="text-left py-3 px-4">Target</th>
                                <th className="text-left py-3 px-4">Proto</th>
                                <th className="text-left py-3 px-4">Port</th>
                            </tr>
                            </thead>
                            <tbody>
                            {recentAlerts.length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="text-center py-16 text-slate-500 text-lg">
                                        No threats detected — Your network is clean and safe
                                    </td>
                                </tr>
                            ) : (
                                recentAlerts.slice(0, 10).map(alert => (
                                    <tr key={alert.id}
                                        className="border-b border-slate-700/50 hover:bg-slate-700/40 transition">
                                        <td className="py-3 px-4 font-mono">{alert.time}</td>
                                        <td className="py-3 px-4 font-bold text-red-400">{alert.type}</td>
                                        <td className="py-3 px-4">
                                                <span
                                                    className={`${getSeverityColor(alert.severity)} px-3 py-1 rounded-full text-xs font-bold`}>
                                                    {alert.severity.toUpperCase()}
                                                </span>
                                        </td>
                                        <td className="py-3 px-4 font-mono text-cyan-300">{alert.source}</td>
                                        <td className="py-3 px-4 font-mono">{alert.destination}</td>
                                        <td className="py-3 px-4">{alert.protocol}</td>
                                        <td className="py-3 px-4 font-mono">{alert.port}</td>
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

export default NIDSDashboard;