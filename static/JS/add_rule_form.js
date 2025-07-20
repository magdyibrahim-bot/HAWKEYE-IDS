function toggleForm() {
    const form = document.getElementById("addRuleForm");
    form.classList.toggle("d-none");
    if (!form.classList.contains("d-none")) {
        form.classList.add("fade-in");
    } else {
        form.classList.remove("fade-in");
    }
}
