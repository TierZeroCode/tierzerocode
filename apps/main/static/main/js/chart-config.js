// Shared Chart.js configuration for Tier Zero C.O.D.E
const TZColors = {
    blue: '#3B82F6',
    green: '#10B981',
    red: '#EF4444',
    amber: '#F59E0B',
    purple: '#8B5CF6',
    cyan: '#06B6D4',
    slate: '#64748B',
    pink: '#EC4899',
    indigo: '#6366F1',
    teal: '#14B8A6',
};

// Chart.js default overrides
if (typeof Chart !== 'undefined') {
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 13;
    Chart.defaults.color = '#64748B';
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.plugins.tooltip.backgroundColor = '#1e293b';
    Chart.defaults.plugins.tooltip.titleFont = { weight: '600' };
    Chart.defaults.plugins.tooltip.padding = 12;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
}

// Palette for chart segments
const TZChartPalette = [
    TZColors.blue, TZColors.green, TZColors.amber, TZColors.red,
    TZColors.purple, TZColors.cyan, TZColors.pink, TZColors.indigo,
    TZColors.teal, TZColors.slate
];
