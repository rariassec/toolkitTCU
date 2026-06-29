import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from toolkitTCU.network_module.core.config import GRAPHICS_FOLDER

def ensure_folder():
    if not os.path.exists(
        GRAPHICS_FOLDER
    ):
        os.makedirs(
            GRAPHICS_FOLDER
        )

def generate_risk_gauge(score):
    ensure_folder()
    fig, ax = plt.subplots(
        figsize=(8,4)
    )
    ax.set_xlim(-1.2,1.2)
    ax.set_ylim(0,1.2)
    ax.axis("off")
    angles = np.linspace(
        np.pi,
        0,
        100
    )
    x = np.cos(angles)
    y = np.sin(angles)

    ax.plot(
        x,
        y,
        linewidth=15
    )
    pointer_angle = (
        np.pi -
        (score / 10) * np.pi
    )
    pointer_x = np.cos(
        pointer_angle
    )
    pointer_y = np.sin(
        pointer_angle
    )
    ax.plot(
        [0,pointer_x],
        [0,pointer_y],
        linewidth=4
    )
    ax.text(
        0,
        0.35,
        f"{score}/10",
        ha="center",
        fontsize=18
    )
    if score >= 9:
        level = "CRITICO"
    elif score >= 7:
        level = "ALTO"
    elif score >= 4:
        level = "MEDIO"
    else:
        level = "BAJO"
    ax.text(
        0,
        0.6,
        level,
        ha="center",
        fontsize=22
    )
    plt.title(
        "Nivel de riesgo general"
    )
    plt.savefig(
    f"{GRAPHICS_FOLDER}/riesgo_general.png",
    bbox_inches="tight"
    )

    plt.close(fig)

def generate_severity_chart(
    vulnerabilities
):
    ensure_folder()
    critical = 0
    high = 0
    medium = 0
    low = 0
    for vuln in vulnerabilities:
        severity = vuln.get(
            "severity",
            "N/A"
        ).upper()
        if severity == "CRITICAL":
            critical += 1
        elif severity == "HIGH":
            high += 1
        elif severity == "MEDIUM":
            medium += 1
        elif severity == "LOW":
            low += 1

    categories = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]
    values = [
        critical,
        high,
        medium,
        low
    ]
    plt.figure(
        figsize=(8,5)
    )
    plt.bar(
        categories,
        values
    )
    plt.title(
        "Distribucion de vulnerabilidades"
    )
    plt.ylabel(
        "Cantidad"
    )

    plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.5
    )
    plt.savefig(
        f"{GRAPHICS_FOLDER}/"
        f"severidades.png",
        bbox_inches="tight"
    )

    plt.close()

def generate_risk_matrix(matrix):
    ensure_folder()
    data = np.array([
        [
            matrix["BAJO"],
            matrix["MEDIO"]
        ],
        [
            matrix["ALTO"],
            matrix["CRITICO"]
        ]
    ])

    fig, ax = plt.subplots(
        figsize=(6,6)
    )
    ax.imshow(data)

    ax.set_xticks(
        [0,1]
    )
    ax.set_yticks(
        [0,1]
    )
    ax.set_xticklabels([
        "Impacto Bajo",
        "Impacto Alto"
    ])
    ax.set_yticklabels([
        "Probabilidad Baja",
        "Probabilidad Alta"
    ])
    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                str(data[i,j]),
                ha="center",
                va="center",
                fontsize=14
            )
    plt.title(
        "Matriz de Riesgos"
    )
    plt.savefig(
        f"{GRAPHICS_FOLDER}/"
        f"matriz_riesgos.png",
        bbox_inches="tight"
    )
    plt.close(fig)
