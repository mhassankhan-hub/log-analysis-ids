// Chart.js helper module for SOC Sentinel Dashboard

let tacticsChartInstance = null;
let timelineChartInstance = null;

const MITRE_COLORS = [
  '#ef4444', // Red
  '#f97316', // Orange
  '#f59e0b', // Amber
  '#06b6d4', // Cyan
  '#8b5cf6', // Purple
  '#3b82f6', // Blue
  '#ec4899', // Pink
  '#10b981'  // Emerald
];

function initOrUpdateTacticsChart(tacticsData) {
  const ctx = document.getElementById('tacticsChart');
  if (!ctx) return;

  const labels = Object.keys(tacticsData || {});
  const data = Object.values(tacticsData || {});

  if (labels.length === 0) {
    labels.push('No Detections');
    data.push(1);
  }

  if (tacticsChartInstance) {
    tacticsChartInstance.data.labels = labels;
    tacticsChartInstance.data.datasets[0].data = data;
    tacticsChartInstance.data.datasets[0].backgroundColor = labels[0] === 'No Detections' ? ['#334155'] : MITRE_COLORS.slice(0, labels.length);
    tacticsChartInstance.update();
    return;
  }

  tacticsChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: labels[0] === 'No Detections' ? ['#334155'] : MITRE_COLORS.slice(0, labels.length),
        borderColor: '#0a0d14',
        borderWidth: 2,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#94a3b8',
            font: { family: 'Inter', size: 11 },
            boxWidth: 12,
            padding: 12
          }
        },
        tooltip: {
          backgroundColor: 'rgba(15, 20, 34, 0.95)',
          titleColor: '#f1f5f9',
          bodyColor: '#38bdf8',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          padding: 10
        }
      },
      cutout: '68%'
    }
  });
}

function initOrUpdateTimelineChart(timelineData) {
  const ctx = document.getElementById('timelineChart');
  if (!ctx) return;

  const labels = (timelineData || []).map(t => {
    // Format "YYYY-MM-DDTHH:MM" to "HH:MM"
    const parts = (t.time_bucket || '').split('T');
    return parts[1] || t.time_bucket || '';
  });
  const data = (timelineData || []).map(t => t.count);

  if (labels.length === 0) {
    labels.push('Now');
    data.push(0);
  }

  if (timelineChartInstance) {
    timelineChartInstance.data.labels = labels;
    timelineChartInstance.data.datasets[0].data = data;
    timelineChartInstance.update();
    return;
  }

  // Create gradient
  const chartCtx = ctx.getContext('2d');
  const gradient = chartCtx.createLinearGradient(0, 0, 0, 240);
  gradient.addColorStop(0, 'rgba(6, 182, 212, 0.4)');
  gradient.addColorStop(1, 'rgba(6, 182, 212, 0.0)');

  timelineChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'Incident Rate',
        data: data,
        borderColor: '#06b6d4',
        backgroundColor: gradient,
        borderWidth: 2,
        fill: true,
        tension: 0.35,
        pointBackgroundColor: '#06b6d4',
        pointBorderColor: '#fff',
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          ticks: {
            color: '#64748b',
            font: { family: 'JetBrains Mono', size: 10 },
            stepSize: 1
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 20, 34, 0.95)',
          titleColor: '#f1f5f9',
          bodyColor: '#38bdf8',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}
