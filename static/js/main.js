// 平滑滚动到锚点
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// 内容加载动画
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
    });
});

// 情感分析图表
function renderSentimentChart(data) {
    if (typeof Chart !== 'undefined' && data) {
        const ctx = document.getElementById('sentimentChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['积极', '中性', '消极'],
                datasets: [{
                    data: [data.positive, data.neutral, data.negative],
                    backgroundColor: [
                        '#28a745',
                        '#ffc107',
                        '#dc3545'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
}