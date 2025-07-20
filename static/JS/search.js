
document.getElementById('ruleSearch').addEventListener('keyup', function () {
    let input = this.value.toLowerCase();
    let rules = document.querySelectorAll('.rule-item');

    rules.forEach(rule => {
        let text = rule.textContent.toLowerCase();
        rule.style.display = text.includes(input) ? 'block' : 'none';
    });
});