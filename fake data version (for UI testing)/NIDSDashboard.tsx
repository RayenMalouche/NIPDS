import React, {useState, useEffect} from 'react';
import {
    LineChart,
    Line,
    BarChart,
    Bar,
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
import {AlertTriangle, Shield, Activity, Network, Clock, TrendingUp} from 'lucide-react';

const NIDSDashboard = () => {
    const [alerts, setAlerts] = useState<any[]>([]); // not used but keeps TS happy
    const [stats, setStats] = useState({
        totalPackets: 0,
        threats: 0,
        blocked: 0,
        normal: 0
    });

    const [trafficData, setTrafficData] = useState<Array<{
        time: string;
        packets: number;
        threats: number;
        normal: number
    }>>([]);

    const [threatTypes, setThreatTypes] = useState<Array<{
        name: string;
        value: number
    }>>([]);

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

    const [isMonitoring, setIsMonitoring] = useState(true);

    // Simulate real-time data updates
    useEffect(() => {
        const interval = setInterval(() => {
            if (isMonitoring) {
                updateData();
            }
        }, 2000);
        return () => clearInterval(interval);
    }, [isMonitoring]);

    const updateData = () => {
        const now = new Date();
        const timeStr = now.toLocaleTimeString();

        // Generate realistic network traffic data
        const newPackets = Math.floor(Math.random() * 500) + 100;
        const newThreats = Math.floor(Math.random() * 10);

        setStats(prev => ({
            totalPackets: prev.totalPackets + newPackets,
            threats: prev.threats + newThreats,
            blocked: prev.blocked + Math.floor(newThreats * 0.8),
            normal: prev.normal + (newPackets - newThreats)
        }));

        // Update traffic chart
        setTrafficData(prev => {
            const updated = [...prev, {
                time: timeStr,
                packets: newPackets,
                threats: newThreats,
                normal: newPackets - newThreats
            }];
            return updated.slice(-20); // Keep last 20 data points
        });

        // Generate new alerts
        if (newThreats > 5) {
            const threatTypes = ['Port Scan', 'DDoS Attempt', 'SQL Injection', 'Brute Force', 'Malware Traffic'];
            const severities = ['High', 'Critical', 'Medium'];
            const newAlert = {
                id: Date.now(),
                type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
                severity: severities[Math.floor(Math.random() * severities.length)],
                source: `192.168.1.${Math.floor(Math.random() * 255)}`,
                destination: `10.0.0.${Math.floor(Math.random() * 255)}`,
                time: timeStr,
                protocol: Math.random() > 0.5 ? 'TCP' : 'UDP',
                port: Math.floor(Math.random() * 65535)
            };

            setRecentAlerts(prev => [newAlert, ...prev].slice(0, 10));
        }

        // Update threat distribution
        setThreatTypes([
            {name: 'Port Scan', value: Math.floor(Math.random() * 30) + 10},
            {name: 'DDoS', value: Math.floor(Math.random() * 20) + 5},
            {name: 'SQL Injection', value: Math.floor(Math.random() * 15) + 3},
            {name: 'Brute Force', value: Math.floor(Math.random() * 25) + 8},
            {name: 'Malware', value: Math.floor(Math.random() * 10) + 2}
        ]);
    };

    const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981'];

    const getSeverityColor = (severity: string): string => {
        switch (severity) {
            case 'Critical':
                return 'bg-red-600 text-white';
            case 'High':
                return 'bg-orange-500 text-white';
            case 'Medium':
                return 'bg-yellow-500 text-black';
            default:
                return 'bg-blue-500 text-white';
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div className="flex items-center gap-3">
                        <Shield className="w-10 h-10 text-blue-400"/>
                        <div>
                            <h1 className="text-3xl font-bold">Network Intrusion Detection System</h1>
                            <p className="text-slate-400">Real-time threat monitoring and analysis</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <button
                            onClick={() => setIsMonitoring(!isMonitoring)}
                            className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                                isMonitoring
                                    ? 'bg-green-600 hover:bg-green-700'
                                    : 'bg-slate-600 hover:bg-slate-700'
                            }`}
                        >
                            {isMonitoring ? '● Monitoring' : '○ Paused'}
                        </button>
                    </div>
                </div>

                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-slate-400 text-sm">Total Packets</p>
                                <p className="text-3xl font-bold mt-1">{stats.totalPackets.toLocaleString()}</p>
                            </div>
                            <Activity className="w-10 h-10 text-blue-400"/>
                        </div>
                    </div>

                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-slate-400 text-sm">Threats Detected</p>
                                <p className="text-3xl font-bold mt-1 text-red-400">{stats.threats}</p>
                            </div>
                            <AlertTriangle className="w-10 h-10 text-red-400"/>
                        </div>
                    </div>

                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-slate-400 text-sm">Blocked</p>
                                <p className="text-3xl font-bold mt-1 text-orange-400">{stats.blocked}</p>
                            </div>
                            <Shield className="w-10 h-10 text-orange-400"/>
                        </div>
                    </div>

                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-slate-400 text-sm">Normal Traffic</p>
                                <p className="text-3xl font-bold mt-1 text-green-400">{stats.normal.toLocaleString()}</p>
                            </div>
                            <Network className="w-10 h-10 text-green-400"/>
                        </div>
                    </div>
                </div>

                {/* Charts Row */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    {/* Traffic Timeline */}
                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                            <TrendingUp className="w-5 h-5 text-blue-400"/>
                            Network Traffic Timeline
                        </h2>
                        <ResponsiveContainer width="100%" height={250}>
                            <LineChart data={trafficData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155"/>
                                <XAxis dataKey="time" stroke="#94a3b8"/>
                                <YAxis stroke="#94a3b8"/>
                                <Tooltip
                                    contentStyle={{backgroundColor: '#1e293b', border: '1px solid #334155'}}
                                    labelStyle={{color: '#94a3b8'}}
                                />
                                <Legend/>
                                <Line type="monotone" dataKey="packets" stroke="#3b82f6" strokeWidth={2}
                                      name="Total Packets"/>
                                <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2}
                                      name="Threats"/>
                            </LineChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Threat Distribution */}
                    <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-red-400"/>
                            Threat Distribution
                        </h2>
                        <ResponsiveContainer width="100%" height={250}>
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
                                    contentStyle={{backgroundColor: '#1e293b', border: '1px solid #334155'}}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Recent Alerts */}
                <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700 rounded-xl p-6">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                        <Clock className="w-5 h-5 text-yellow-400"/>
                        Recent Security Alerts
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                            <tr className="border-b border-slate-700 text-slate-400 text-sm">
                                <th className="text-left py-3 px-4">Time</th>
                                <th className="text-left py-3 px-4">Type</th>
                                <th className="text-left py-3 px-4">Severity</th>
                                <th className="text-left py-3 px-4">Source IP</th>
                                <th className="text-left py-3 px-4">Destination</th>
                                <th className="text-left py-3 px-4">Protocol</th>
                                <th className="text-left py-3 px-4">Port</th>
                            </tr>
                            </thead>
                            <tbody>
                            {recentAlerts.length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="text-center py-8 text-slate-500">
                                        No alerts yet. Monitoring network traffic...
                                    </td>
                                </tr>
                            ) : (
                                recentAlerts.map((alert) => (
                                    <tr key={alert.id}
                                        className="border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors">
                                        <td className="py-3 px-4 text-sm">{alert.time}</td>
                                        <td className="py-3 px-4 text-sm font-semibold">{alert.type}</td>
                                        <td className="py-3 px-4">
                        <span
                            className={`${getSeverityColor(alert.severity)} px-3 py-1 rounded-full text-xs font-semibold`}>
                          {alert.severity}
                        </span>
                                        </td>
                                        <td className="py-3 px-4 text-sm font-mono">{alert.source}</td>
                                        <td className="py-3 px-4 text-sm font-mono">{alert.destination}</td>
                                        <td className="py-3 px-4 text-sm">{alert.protocol}</td>
                                        <td className="py-3 px-4 text-sm">{alert.port}</td>
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