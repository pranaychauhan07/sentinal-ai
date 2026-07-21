"""Report Theme System — the task's named "Theme System".

A `ReportTheme` is the one typed object every renderer (`html_renderer.py`,
`pdf_renderer.py`, `docx_renderer.py`) reads for color/branding/layout
decisions, so a new theme or a custom org brand never requires touching
renderer code (constitution §1.1, "the correct solution... never requires a
rewrite for a new instance of the same shape"). `LIGHT_THEME`/`DARK_THEME`
are the two built-in presets (HTML export's "dark mode / light mode"
requirement); a caller passes any other `ReportTheme` instance for custom
branding — this is the "future template plugins" extensibility point named
in the task: a plugin registers itself by handing renderers its own
`ReportTheme`/template pair, never by this module growing a mutable
registry (constitution §2, "avoid global state").
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.reporting.exceptions import UnknownThemeError


class ReportTheme(BaseModel):
    """Everything a renderer needs to brand and style a report. Frozen —
    a theme is configuration, never mutated mid-render."""

    model_config = ConfigDict(frozen=True)

    name: str
    #: `True` for a dark-background theme (HTML export's dark-mode toggle;
    #: PDF/DOCX always render on a light/print-safe background regardless of
    #: this flag, since a dark PDF page is not a print-friendly artifact —
    #: `dark_mode` only ever affects `html_renderer.py`).
    dark_mode: bool = False
    primary_color: str = "#1f6feb"
    secondary_color: str = "#8b949e"
    background_color: str = "#ffffff"
    text_color: str = "#0d1117"
    accent_color: str = "#d29922"
    font_family: str = "Helvetica, Arial, sans-serif"
    #: Organization branding — every field optional; a `None` value means
    #: "omit this element," never a fabricated placeholder (constitution
    #: §1.7).
    organization_name: str | None = None
    #: Base64 `data:image/...` URI or `None`. Never a filesystem path — see
    #: `asset_manager.py` for how a raw image is turned into this string.
    logo_data_uri: str | None = None
    header_text: str | None = None
    footer_text: str | None = None
    page_numbering: bool = True


#: Built-in presets — HTML export's "Dark mode / Light mode" requirement.
LIGHT_THEME = ReportTheme(
    name="light",
    dark_mode=False,
    primary_color="#1f6feb",
    secondary_color="#57606a",
    background_color="#ffffff",
    text_color="#0d1117",
    accent_color="#9a6700",
)

DARK_THEME = ReportTheme(
    name="dark",
    dark_mode=True,
    primary_color="#58a6ff",
    secondary_color="#8b949e",
    background_color="#0d1117",
    text_color="#c9d1d9",
    accent_color="#d29922",
)

#: Read-only lookup by name — a documented, immutable module-level mapping
#: (constitution §2's accepted exception: "an explicitly-designed,
#: documented... singleton", never mutated after import). A custom theme is
#: passed directly to a renderer/export call, never registered here.
BUILT_IN_THEMES: dict[str, ReportTheme] = {
    LIGHT_THEME.name: LIGHT_THEME,
    DARK_THEME.name: DARK_THEME,
}


def resolve_theme(theme: ReportTheme | str | None) -> ReportTheme:
    """Normalizes the three ways a caller may specify a theme (an already-
    built `ReportTheme`, a built-in preset name, or `None` for the default)
    into a concrete `ReportTheme` — the one place this lookup happens, so
    every renderer/service shares identical fallback behavior."""
    if theme is None:
        return LIGHT_THEME
    if isinstance(theme, ReportTheme):
        return theme
    resolved = BUILT_IN_THEMES.get(theme)
    if resolved is None:
        raise UnknownThemeError(
            f"Unknown built-in theme '{theme}'.",
            details={"theme": theme, "available": sorted(BUILT_IN_THEMES)},
        )
    return resolved
