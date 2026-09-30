let questions = [];

document.addEventListener("DOMContentLoaded", async () => {
    try {
        const res = await fetch('/api/quiz');
        questions = await res.json();
        const form = document.getElementById('quizForm');
        if (form) {
            form.innerHTML = questions.map(item => `
                <div style="margin-bottom:1.5rem;">
                    <p><strong>${item.id}. ${item.question}</strong></p>
                    ${item.options.map(opt => `
                        <label style="display:block; margin:4px 0; color:#94a3b8; cursor:pointer;">
                            <input type="radio" name="${item.id}" value="${opt[0]}"> ${opt}
                        </label>
                    `).join('')}
                </div>
            `).join('');
        }
    } catch (e) {
        console.error("Quiz questions failed to load", e);
    }
});

async function submitQuiz() {
    const payload = {};
    questions.forEach(q => {
        const el = document.querySelector(`input[name="${q.id}"]:checked`);
        if (el) payload[q.id] = el.value;
    });

    const res = await fetch('/api/quiz/submit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
    const result = await res.json();
    const resBox = document.getElementById('quizResult');
    resBox.classList.remove('hidden');
    resBox.innerHTML = `
        <h3>Awareness Score: ${result.overall_score}%</h3>
        <p>Correct: ${result.correct_answers} / ${result.total_questions}</p>
        <h4>Recommendations:</h4>
        <ul>${result.recommendations.map(r => `<li>${r}</li>`).join('') || '<li>Great awareness! Keep practicing defensive hygiene.</li>'}</ul>
    `;
}