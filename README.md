# vuln-watch

Agente de **solo lectura** que revisa todos los proyectos contra vulnerabilidades publicadas (CVE/GHSA) e informa riesgo y mitigación.

## Uso
- `/cve-check CVE-2026-123007` — revisa un CVE concreto en todos los proyectos.
- `/cve-check recientes` — todas las vulnerabilidades conocidas en dependencias + CVEs de infraestructura de los últimos 2 días.
- Revisión automática diaria 7:00 am (CDMX) mediante una tarea programada de Claude Code en el entorno `vuln-watch`.

## Componentes
| Ruta | Qué es |
|---|---|
| `.claude/skills/cve-check/SKILL.md` | Flujo del comando `/cve-check` |
| `.claude/agents/vuln-auditor.md` | Subagente auditor (solo lectura) |
| `.claude/settings.json` | Reglas que bloquean escrituras, instalaciones, push y SQL en Supabase |
| `scripts/scan.py` | Escáner: lee lockfiles (npm, Go, PyPI), imágenes Docker, configs nginx, Terraform; consulta OSV, NVD, MITRE y CISA KEV |
| `projects.json` | Proyectos a revisar (repos, Supabase, carpetas locales) |

## Fuentes
OSV.dev (agrega GitHub Advisories, Go, PyPI, npm), NVD, CVE.org/MITRE, CISA KEV.

## Límites
- Las versiones de software instaladas en servidores (p. ej. `nginx -v` en el VPS de rejovi) no están en el repo: aparecen como "Por confirmar".
- Las imágenes Docker se revisan por etiqueta, no se descargan ni se analizan capa por capa.
- El escáner de NVD por palabra clave es ruidoso; el agente filtra los falsos positivos.
