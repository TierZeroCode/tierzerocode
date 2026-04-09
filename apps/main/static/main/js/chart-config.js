// Tier Zero C.O.D.E — Chart.js Configuration
// Industrial precision palette using OKLCH-derived hex values

const TZColors = {
    blue:   '#4B7BE5',  // oklch(0.63 0.195 255)
    green:  '#2EB67D',  // oklch(0.68 0.18 155)
    red:    '#E0503A',  // oklch(0.63 0.215 25)
    amber:  '#D49B18',  // oklch(0.78 0.155 85)
    purple: '#8B5CF6',  // oklch(0.58 0.20 295)
    cyan:   '#0EA5E9',
    slate:  '#6B7A8D',  // oklch(0.55 0.022 260)
    pink:   '#DB2777',
    indigo: '#6366F1',
    teal:   '#14B8A6',
};

if (typeof Chart !== 'undefined') {
    Chart.defaults.font.family = "'Archivo', sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.font.weight = 400;
    Chart.defaults.color = '#6B7A8D';
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.plugins.tooltip.backgroundColor = '#1A1E2E';
    Chart.defaults.plugins.tooltip.titleFont = { weight: 600, size: 12 };
    Chart.defaults.plugins.tooltip.bodyFont = { size: 11 };
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 2;
    Chart.defaults.plugins.tooltip.displayColors = true;
    Chart.defaults.plugins.tooltip.boxWidth = 8;
    Chart.defaults.plugins.tooltip.boxHeight = 8;
    Chart.defaults.plugins.tooltip.boxPadding = 4;
}

const TZChartPalette = [
    TZColors.blue, TZColors.green, TZColors.amber, TZColors.red,
    TZColors.purple, TZColors.cyan, TZColors.pink, TZColors.indigo,
    TZColors.teal, TZColors.slate
];

// Helper: get border color based on current theme
function tzChartBorderColor() {
    return document.documentElement.classList.contains('dark') ? '#1A1E2E' : '#FAFBFD';
}
