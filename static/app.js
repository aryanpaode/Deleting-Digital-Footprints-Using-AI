(() => {
    const overlay = document.getElementById("busyOverlay");
    const busyTitle = document.getElementById("busyTitle");
    const busyText = document.getElementById("busyText");

    document.querySelectorAll(".js-busy-form").forEach((form) => {
        form.addEventListener("submit", () => {
            if (!form.checkValidity()) {
                return;
            }

            if (overlay) {
                busyTitle.textContent =
                    form.dataset.busyTitle || "Working securely…";

                busyText.textContent =
                    form.dataset.busyText ||
                    "Please keep this page open while the local pipeline runs.";

                overlay.classList.add("visible");
                overlay.setAttribute("aria-hidden", "false");
            }
        });
    });

    document.querySelectorAll(".flash-close").forEach((button) => {
        button.addEventListener("click", () => {
            button.closest(".flash")?.remove();
        });
    });

    const menuButton = document.getElementById("menuButton");
    const sidebar = document.querySelector(".sidebar");

    if (menuButton && sidebar) {
        menuButton.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }

    const filterButtons = document.querySelectorAll(".filter-btn");
    const analysisRows = document.querySelectorAll(".analysis-row");

    filterButtons.forEach((button) => {
        button.addEventListener("click", () => {
            filterButtons.forEach((item) =>
                item.classList.remove("active")
            );

            button.classList.add("active");

            const filter = button.dataset.filter;

            analysisRows.forEach((row) => {
                const risk = row.dataset.risk;

                let show = filter === "all";

                if (filter === "high") {
                    show = risk === "high" || risk === "critical";
                } else if (filter === "medium") {
                    show = risk === "medium";
                } else if (filter === "low") {
                    show = risk === "low";
                }

                row.hidden = !show;
            });
        });
    });

    const verifyForm = document.querySelector(".verify-form");
    const progress = document.getElementById("verifyProgress");
    const answeredCount = document.getElementById("answeredCount");
    const submitButton = document.getElementById("verificationSubmit");

    if (verifyForm && progress && answeredCount && submitButton) {
        const radioGroups = new Set(
            [...verifyForm.querySelectorAll('input[type="radio"]')]
                .map((input) => input.name)
        );

        const updateProgress = () => {
            let answered = 0;

            radioGroups.forEach((name) => {
                if (
                    verifyForm.querySelector(
                        `input[name="${CSS.escape(name)}"]:checked`
                    )
                ) {
                    answered += 1;
                }
            });

            const total = radioGroups.size;
            const percent = total ? (answered / total) * 100 : 100;

            answeredCount.textContent = answered;
            progress.style.width = `${percent}%`;
            submitButton.disabled = answered !== total;
        };

        verifyForm
            .querySelectorAll('input[type="radio"]')
            .forEach((input) => {
                input.addEventListener("change", updateProgress);
            });

        updateProgress();
    }

    const referenceImage = document.getElementById("referenceImage");
    const consentVisual = document.getElementById("consentVisual");
    const visualConsentCard = document.getElementById("visualConsentCard");
    const previewCard = document.getElementById("imagePreviewCard");
    const previewImage = document.getElementById("imagePreview");
    const previewName = document.getElementById("imagePreviewName");

    if (referenceImage && consentVisual) {
        const updateReferenceImageState = () => {
            const file = referenceImage.files?.[0];
            const available = Boolean(file);

            consentVisual.disabled = !available;
            visualConsentCard?.classList.toggle("disabled", !available);

            if (!available) {
                consentVisual.checked = false;
                if (previewCard) previewCard.hidden = true;
                if (previewImage) previewImage.removeAttribute("src");
                return;
            }

            if (previewName) previewName.textContent = file.name;
            if (previewCard) previewCard.hidden = false;

            if (previewImage) {
                const reader = new FileReader();
                reader.addEventListener("load", () => {
                    previewImage.src = String(reader.result || "");
                });
                reader.readAsDataURL(file);
            }
        };

        referenceImage.addEventListener("change", updateReferenceImageState);
        updateReferenceImageState();
    }


    const phase4FilterButtons = document.querySelectorAll(".phase4-filter-btn");
    const phase4TaskCards = document.querySelectorAll(".phase4-task-card");

    phase4FilterButtons.forEach((button) => {
        button.addEventListener("click", () => {
            phase4FilterButtons.forEach((item) => item.classList.remove("active"));
            button.classList.add("active");

            const filter = button.dataset.phase4Filter || "all";

            phase4TaskCards.forEach((card) => {
                const status = card.dataset.phase4Status || "";
                const approval = card.dataset.phase4Approval || "";

                let show = filter === "all";
                if (filter === "approval") {
                    show = status === "awaiting_approval" && approval === "pending";
                } else if (filter === "active") {
                    show = [
                        "in_progress",
                        "submitted",
                        "pending_external_confirmation",
                    ].includes(status);
                } else if (filter === "completed") {
                    show = status === "completed";
                }

                card.hidden = !show;
            });
        });
    });


    const phase4DecisionForm = document.querySelector(".phase4-decision-form");
    if (phase4DecisionForm) {
        const decisionGroups = new Set(
            [...phase4DecisionForm.querySelectorAll('input[type="radio"]')]
                .map((input) => input.name)
        );
        const remainingPill = document.querySelector(".decision-progress-pill");
        const saveButton = phase4DecisionForm.querySelector('button[type="submit"]');

        const updateDecisionProgress = () => {
            let answered = 0;
            decisionGroups.forEach((name) => {
                if (phase4DecisionForm.querySelector(`input[name="${CSS.escape(name)}"]:checked`)) {
                    answered += 1;
                }
            });

            const remaining = decisionGroups.size - answered;
            if (remainingPill) {
                remainingPill.textContent = remaining === 0
                    ? "Ready to save"
                    : `${remaining} remaining`;
            }
            if (saveButton) saveButton.disabled = remaining !== 0;
        };

        phase4DecisionForm.querySelectorAll('input[type="radio"]').forEach((input) => {
            input.addEventListener("change", updateDecisionProgress);
        });
        updateDecisionProgress();
    }

    document.querySelectorAll(".js-copy-request").forEach((button) => {
        button.addEventListener("click", async () => {
            const targetId = button.dataset.copyTarget;
            const field = targetId ? document.getElementById(targetId) : null;
            if (!field) return;

            const text = field.value || field.textContent || "";
            try {
                await navigator.clipboard.writeText(text);
                const original = button.textContent;
                button.textContent = "Copied";
                window.setTimeout(() => { button.textContent = original; }, 1400);
            } catch (_error) {
                field.focus();
                field.select?.();
                document.execCommand?.("copy");
            }
        });
    });
})();
