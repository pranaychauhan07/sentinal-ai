"""Report Template Engine — the task's named "Report Template Engine" /
"Template Engine".

Thin wrapper around a Jinja2 `Environment`, rooted at this package's own
`templates/` directory. This is the module the task's "template injection"
security requirement is about, and the defense here is structural, not a
runtime filter:

1. **Only named, trusted template files are ever compiled as template
   source.** `render()` takes a `template_name` restricted to
   `KNOWN_TEMPLATES` (an explicit allowlist) — never a caller-supplied
   template *string*. Case data (finding titles, IOC values, chat-adjacent
   free text) is only ever passed as a `context` variable, never
   interpolated into the template source itself. A classic Jinja2
   injection (`{{ ''.__class__... }}` reaching `render()`) requires
   attacker-controlled text to *become* template source; here it can only
   ever become the *value* of a variable, which Jinja2 does not
   re-evaluate as code.
2. **Autoescaping is on for every template** (`select_autoescape`), so any
   HTML-shaped case data (a finding description containing `<script>`) is
   escaped on output, not executed by a report viewer's browser — the same
   XSS defense constitution §10 requires ("unsafe embedded content").
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateError, select_autoescape

from core.reporting.exceptions import TemplateRenderError

_TEMPLATES_DIR = Path(__file__).parent / "templates"

#: The only template names `render()` accepts — see module docstring point 1.
KNOWN_TEMPLATES = frozenset({"report.html.j2"})


class ReportTemplateEngine:
    def __init__(self, *, templates_dir: Path = _TEMPLATES_DIR) -> None:
        self._environment = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "htm", "xml", "j2"]),
        )

    def render(self, template_name: str, **context: object) -> str:
        if template_name not in KNOWN_TEMPLATES:
            raise TemplateRenderError(
                f"'{template_name}' is not a known report template.",
                details={"template_name": template_name, "known": sorted(KNOWN_TEMPLATES)},
            )
        try:
            template = self._environment.get_template(template_name)
            return template.render(**context)
        except TemplateError as exc:
            raise TemplateRenderError(
                f"Failed to render template '{template_name}': {exc}",
                details={"template_name": template_name, "error": str(exc)},
            ) from exc
