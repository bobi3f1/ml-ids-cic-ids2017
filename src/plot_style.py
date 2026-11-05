"""Единен стил на фигурите (палитра, шрифт, оси, български формат на числата) за доклада и презентацията."""
import locale

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

from config import FIG_DIR  # noqa: E402

# Категориална палитра – слотовете се присвояват винаги в този ред.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
BLUE, ORANGE, AQUA, YELLOW = SERIES[:4]
SEQ_BLUES = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"

CLASS_COLORS = {"BENIGN": BLUE, "ATTACK": ORANGE}       # нормален трафик / атака
ALG_COLORS = {"RF": BLUE, "KNN": ORANGE, "MLP": AQUA, "LR": YELLOW}   # фиксиран цвят за всеки алгоритъм


def _font():
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in ("Segoe UI", "Arial", "DejaVu Sans"):
        if name in available:
            return name
    return "sans-serif"


def fmt(value, decimals=0):
    """Число в български формат: интервал за хилядите, запетая за десетичните (128 027; 99,97)."""
    text = f"{value:,.{decimals}f}"
    return text.replace(",", " ").replace(".", ",")


THOUSANDS = matplotlib.ticker.FuncFormatter(lambda v, _: fmt(v))


SUFFIX = ""          # "_slide" – варианти на фигурите за презентацията (по-широки панели, по-едър шрифт)


def slide_mode(on=True, scale=1.3):
    """Включва/изключва режима за фигури на слайдове."""
    global SUFFIX
    SUFFIX = "_slide" if on else ""
    apply(scale if on else 1.0)


def apply(scale=1.0):
    for name in ("bg-BG", "bg_BG.UTF-8", "Bulgarian_Bulgaria.1251"):
        try:
            locale.setlocale(locale.LC_NUMERIC, name)
            plt.rcParams["axes.formatter.use_locale"] = True   # десетична запетая по осите
            break
        except locale.Error:
            continue
    plt.rcParams.update({
        "font.family": _font(),
        "font.size": 10.5 * scale,
        "axes.titlesize": 12 * scale,
        "axes.titleweight": "semibold",
        "axes.titlelocation": "left",
        "axes.labelsize": 10.5 * scale,
        "axes.labelcolor": INK_2,
        "axes.edgecolor": AXIS,
        "axes.linewidth": 0.8,
        "axes.facecolor": SURFACE,
        "axes.grid": True,
        "axes.axisbelow": True,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "grid.linestyle": "-",
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK_2,
        "ytick.labelcolor": INK_2,
        "legend.frameon": False,
        "legend.fontsize": 10 * scale,
        "figure.facecolor": SURFACE,
        "figure.dpi": 110,
        "xtick.labelsize": 10.5 * scale,
        "ytick.labelsize": 10.5 * scale,
        "savefig.dpi": 200,
        "savefig.facecolor": SURFACE,
        "lines.linewidth": 2,
        "lines.solid_capstyle": "round",
        "text.color": INK,
    })


def grid(n, ncols=2, panel=(6.0, 4.2), **kw):
    """Фигура с n панела в мрежа с ncols колони; връща (fig, плосък списък с осите)."""
    nrows = (n + ncols - 1) // ncols
    if SUFFIX == "_slide" and ncols == 2 and nrows == 2:
        panel = (6.6, 3.05)        # формат ~2,15 : 1 – запълва зоната за съдържание на слайда
    fig, axes = plt.subplots(nrows, ncols, figsize=(panel[0] * ncols, panel[1] * nrows), squeeze=False, **kw)
    flat = list(axes.ravel())
    for ax in flat[n:]:
        ax.set_visible(False)
    return fig, flat[:n]


def top_legend(fig, labels_colors, line=False):
    """Една обща легенда над панелите (за слайдовете, където легендите в панелите закриват данни)."""
    from matplotlib.lines import Line2D
    handles = [Line2D([0], [0], color=c, lw=2.5, label=l) if line else
               Line2D([0], [0], color=c, marker="o", lw=0, ms=9, label=l) for l, c in labels_colors]
    fig.legend(handles=handles, loc="upper center", ncols=len(handles), bbox_to_anchor=(0.5, 1.06),
               frameon=False)


def save(fig, name):
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    path = FIG_DIR / f"{name}{SUFFIX}.png"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def bar_labels(ax, bars, decimals=0, suffix="", color=INK_2, fontsize=9):
    for b in bars:
        h = b.get_height()
        ax.annotate(fmt(h, decimals) + suffix, (b.get_x() + b.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", color=color, fontsize=fontsize)
