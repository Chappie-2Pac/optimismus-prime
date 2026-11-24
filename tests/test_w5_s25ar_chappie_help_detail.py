"""Adversarial tests for S25AR help-detail resolution."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = REPO_ROOT / "tests" / "support" / "w5_s25ar_chappie_help_detail.py"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ar_chappie_help_detail as s25ar  # noqa: E402


EXPECTED_RECORDS = (
    ("A", "analyze", ("analysis", "analyse"), "A) ANALYZE\n\nZweck:\n- Stelle eine klare Aufgabe in Alltagssprache.\n- Chappie antwortet strukturiert und nachvollziehbar.\n\nTypische Eingaben:\n- \"Analysiere das Projekt und fasse die Module zusammen.\"\n- \"Vergleiche Modul X und Y und nenne Risiken.\"\n- \"Erstelle eine Checkliste fuer einen neuen Workflow.\"\n\nErwartete Ausgaben:\n- execution_plan (Plan mit Schritten)\n- execution_summary (kurze Zusammenfassung)\n- optionale Artefakte in storage/artifacts\n\nFuer LLMs (Template):\n1) Ziel als 1 Satz nennen.\n2) Fehlende Infos als Fragen listen.\n3) Dann einen klaren Auftrag an Chappie formulieren.\n\nTipp:\n- Wenn du nicht weisst, wo du anfangen sollst: frag nach einer\n  Minimalversion oder nach einem 3-Schritte-Vorgehen.", "A) ANALYZE\n\nPurpose:\n- Ask a clear task in plain language.\n- Chappie replies with a structured, traceable answer.\n\nTypical inputs:\n- \"Analyze the project and summarize the modules.\"\n- \"Compare module X vs Y and list risks.\"\n- \"Create a checklist for a new workflow.\"\n\nExpected outputs:\n- execution_plan (step plan)\n- execution_summary (short summary)\n- optional artifacts in storage/artifacts\n\nFor LLMs (template):\n1) State the goal in 1 sentence.\n2) List missing info as questions.\n3) Then send a clear instruction to Chappie.\n\nTip:\n- If unsure, ask for a minimal version or a 3-step approach."),
    ("B", "workflow", ("wf", "workflows"), "B) WORKFLOW\n\nZweck:\n- Wiederholbare Ablaufe aus YAML-Dateien starten.\n\nBeispiele:\n- python scripts/run_chappie.py --mode workflow\n- python scripts/run_chappie.py --mode workflow --workflow-path workflows/examples/01_self_inspection.yaml\n- python scripts/run_chappie.py --mode workflow --workflow-id module_documentation\n\nLLM-Workflow:\n- workflows/examples/04_llm_summary.yaml (benoetigt LLM-Config)\n\nAusgaben:\n- Markdown-Artefakte im Workflow-Ordner\n- Registry in storage/artifacts/workflow_versions.json\n\nFuer LLMs:\n- Waehl einen Workflow, setze Pfade, pruefe constraints.\n- Verwende --workflow-validate-only fuer schnelle Checks.", "B) WORKFLOW\n\nPurpose:\n- Run repeatable pipelines defined in YAML.\n\nExamples:\n- python scripts/run_chappie.py --mode workflow\n- python scripts/run_chappie.py --mode workflow --workflow-path workflows/examples/01_self_inspection.yaml\n- python scripts/run_chappie.py --mode workflow --workflow-id module_documentation\n\nLLM workflow:\n- workflows/examples/04_llm_summary.yaml (requires LLM config)\n\nOutputs:\n- Markdown artifacts in the workflow output folder\n- Registry in storage/artifacts/workflow_versions.json\n\nFor LLMs:\n- Pick a workflow, set paths, validate constraints.\n- Use --workflow-validate-only for quick checks."),
    ("C", "pipeline", ("llm-pipeline", "data"), "C) PIPELINE\n\nZweck:\n- Daten sammeln, reinigen, Teaching-Units bauen.\n\nMinimal (Lite-Mode):\n- python scripts/run_chappie.py --mode llm-pipeline --pipeline-task \"Notes\" --pipeline-source data/ --pipeline-auto-verify\n- Preset: --pipeline-preset standard-full|accuracy-high|accuracy-max|train-curriculum|train-unsloth (repeatable/comma-separated)\n\nMit Transkription + OCR:\n- --pipeline-transcribe --pipeline-transcribe-ocr-pdf\n- Qualitaet: --pipeline-transcribe-quality-preset max-accuracy|high-accuracy|balanced\n- Optional: --pipeline-transcribe-prefer-subtitles\n- Optional: --pipeline-transcribe-subtitle-policy require|prefer|off\n- Optional: --pipeline-transcribe-subtitle-quality-check\n- Optional: --pipeline-transcribe-subtitle-min-chars 200\n- Optional: --pipeline-transcribe-subtitle-audit --pipeline-transcribe-subtitle-audit-threshold 0.85\n- Optional: --pipeline-transcribe-subtitle-audit-fallback (Audit -> ASR Fallback)\n- Optional: --pipeline-transcribe-subtitle-missing-path <path>\n- Optional: --pipeline-transcribe-ocr-policy fallback|heuristic|force|off\n- Optional: --pipeline-transcribe-language-order de,en\n- Optional: --pipeline-scan-language-map '{\"de\":[\"de\",\"deu\"],\"en\":[\"en\",\"eng\"]}'\n- Optional: --pipeline-scan-language de --pipeline-scan-language en\n- Optional: --pipeline-scan-language-include-unknown\n\nPerformance (große Runs):\n- --pipeline-performance-preset auto (auto: per-file Transcribe-Ausgabe)\n- Optional: --pipeline-transcribe-faster-whisper-batch-size 8\n- Default: faster-whisper compute_type float32 (GPU stabil).\n- Default: Rust-Engines (Fallback Python wenn Binary fehlt).\n- Override: --pipeline-chunk-engine python --pipeline-dedup-engine python\n- Optional: --pipeline-chunk-tokenizer-json /pfad/tokenizer.json (Rust Chunking)\n- Optional: --pipeline-parquet-mirror --pipeline-parquet-dir <dir>\n- Auto: --pipeline-auto-deny (ffprobe-basierte Denylist fuer fehlerhafte MP4s pro Run)\n- Disable: --pipeline-no-auto-deny (Auto-Denylist aus)\n- Auto: --pipeline-transcribe-auto-tune (GPU-aware faster-whisper-Optimierung fuer Durchsatz)\n- Optional: --pipeline-fast-transcribe-preextract (ffmpeg Audio-Demux parallel vor Fast-Transcribe)\n- Optional: --pipeline-fast-transcribe-preextract-hwaccel cuda --pipeline-fast-transcribe-preextract-workers 2\n- Auto-Batch (grosse lokale Quellen): --pipeline-auto-batch-threshold-gb 5 --pipeline-auto-batch-target-gb 2\n- Disable: --pipeline-no-auto-batch\n\nLLM-Refinement + Curriculum:\n- --pipeline-teach-llm --pipeline-teach-llm-quantization 4bit --pipeline-curriculum\n- Optional: --pipeline-teach-llm-max-output-chars 4000\n- Optional: --pipeline-teach-llm-require-quote --pipeline-teach-llm-max-retries 2\n\nOutputs:\n- storage/pipelines/<run_id>/ (manifest, teaching units, reports)\n\nRuntime:\n- `skip_step` beendet den aktuellen Pipeline-Schritt und springt zum naechsten.\n\nFuer LLMs:\n- Frage nach Quelle(n), Ziel, Sprache, Groesse, OCR ja/nein.\n- Dann baue die Pipeline-Flags daraus zusammen.", "C) PIPELINE\n\nPurpose:\n- Collect, clean, and build teaching units for training.\n\nMinimal (lite mode):\n- python scripts/run_chappie.py --mode llm-pipeline --pipeline-task \"Notes\" --pipeline-source data/ --pipeline-auto-verify\n- Preset: --pipeline-preset standard-full|accuracy-high|accuracy-max|train-curriculum|train-unsloth (repeatable/comma-separated)\n\nWith transcription + OCR:\n- --pipeline-transcribe --pipeline-transcribe-ocr-pdf\n- Quality: --pipeline-transcribe-quality-preset max-accuracy|high-accuracy|balanced\n- Optional: --pipeline-transcribe-prefer-subtitles\n- Optional: --pipeline-transcribe-subtitle-policy require|prefer|off\n- Optional: --pipeline-transcribe-subtitle-quality-check\n- Optional: --pipeline-transcribe-subtitle-min-chars 200\n- Optional: --pipeline-transcribe-subtitle-audit --pipeline-transcribe-subtitle-audit-threshold 0.85\n- Optional: --pipeline-transcribe-subtitle-audit-fallback (audit -> ASR fallback)\n- Optional: --pipeline-transcribe-subtitle-missing-path <path>\n- Optional: --pipeline-transcribe-ocr-policy fallback|heuristic|force|off\n- Optional: --pipeline-transcribe-language-order de,en\n- Optional: --pipeline-scan-language-map '{\"de\":[\"de\",\"deu\"],\"en\":[\"en\",\"eng\"]}'\n- Optional: --pipeline-scan-language de --pipeline-scan-language en\n- Optional: --pipeline-scan-language-include-unknown\n\nPerformance (large runs):\n- --pipeline-performance-preset auto (auto: per-file transcribe output)\n- Optional: --pipeline-transcribe-faster-whisper-batch-size 8\n- Default: faster-whisper compute_type float32 (GPU stable).\n- Default: rust engines (fallback to python if binary missing).\n- Override: --pipeline-chunk-engine python --pipeline-dedup-engine python\n- Optional: --pipeline-chunk-tokenizer-json /path/to/tokenizer.json (rust chunking)\n- Optional: --pipeline-parquet-mirror --pipeline-parquet-dir <dir>\n- Auto: --pipeline-auto-deny (ffprobe-based denylist for corrupt MP4s each run)\n- Disable: --pipeline-no-auto-deny (turn off auto denylist)\n- Auto: --pipeline-transcribe-auto-tune (GPU-aware faster-whisper tuning for throughput)\n- Optional: --pipeline-fast-transcribe-preextract (parallel ffmpeg audio demux before fast transcribe)\n- Optional: --pipeline-fast-transcribe-preextract-hwaccel cuda --pipeline-fast-transcribe-preextract-workers 2\n- Auto-batch (large local sources): --pipeline-auto-batch-threshold-gb 5 --pipeline-auto-batch-target-gb 2\n- Disable: --pipeline-no-auto-batch\n\nLLM refinement + curriculum:\n- --pipeline-teach-llm --pipeline-teach-llm-quantization 4bit --pipeline-curriculum\n- Optional: --pipeline-teach-llm-max-output-chars 4000\n- Optional: --pipeline-teach-llm-require-quote --pipeline-teach-llm-max-retries 2\n\nOutputs:\n- storage/pipelines/<run_id>/ (manifest, teaching units, reports)\n\nRuntime:\n- `skip_step` ends the current pipeline step and moves to the next.\n\nFor LLMs:\n- Ask for sources, goal, language, size, OCR yes/no.\n- Then compose the pipeline flags accordingly."),
    ("Y", "pipeline-builder", ("pipeline_builder", "pipebuilder"), "Y) PIPELINE BUILDER\n\nZweck:\n- Interaktiver TUI-Builder fuer Pipeline-Presets.\n\nStart:\n- pipeline-builder\n\nAblauf:\n- Preset waehlen, Quellen/Keywords setzen, Features togglen.\n- Auto-Preflight prueft Basics (ohne Netz checks per Default).\n- Optional: Pipeline direkt starten.", "Y) PIPELINE BUILDER\n\nPurpose:\n- Interactive TUI builder for pipeline presets.\n\nStart:\n- pipeline-builder\n\nFlow:\n- Pick a preset, set sources/terms, toggle features.\n- Auto-preflight checks basics (no network reachability by default).\n- Optionally run the pipeline right away."),
    ("W", "workflow-builder", ("workflow_builder", "wf-builder"), "W) WORKFLOW BUILDER\n\nZweck:\n- Interaktiver Builder fuer YAML-Workflows.\n\nStart:\n- workflow-builder\n\nAblauf:\n- Workflow auswaehlen, Auto-Preflight (Validate-only).\n- Optional: Workflow direkt starten.", "W) WORKFLOW BUILDER\n\nPurpose:\n- Interactive builder for YAML workflows.\n\nStart:\n- workflow-builder\n\nFlow:\n- Select workflow, auto-preflight (validate-only).\n- Optionally run the workflow right away."),
    ("O", "connectors", ("connector", "connectors"), "O) CONNECTORS\n\nZweck:\n- Connector-Library fuer Datei/Netz-Quellen.\n\nStart:\n- connectors --list\n- connectors --connector filewatch --execute\n\nConfig:\n- storage/connectors.json (Connector-Namen -> Config).\n\nHinweis:\n- Netzwerk-Connectoren brauchen Access Guard + Network Policy.", "O) CONNECTORS\n\nPurpose:\n- Connector library for file/network sources.\n\nStart:\n- connectors --list\n- connectors --connector filewatch --execute\n\nConfig:\n- storage/connectors.json (connector name -> config).\n\nNote:\n- Network connectors require Access Guard + Network Policy."),
    ("U", "hub", ("hub-server", "hub-client", "hub-pair"), "U) HUB\n\nZweck:\n- Multi-Device Hub mit Access Guard Zertifikaten.\n\nServer starten:\n- hub (CLI) oder python scripts/chappie_hub.py\n\nClient Beispiele:\n- python scripts/hub_client.py --action status --host <hub> --token <token> --cert <cert>\n- python scripts/hub_client.py --action jobs --limit 50\n- python scripts/hub_client.py --action run --execute -- --pipeline-source data/\n\nPairing (Datei-basiert):\n- Device: python scripts/hub_pair_device.py --action request --hub-host <hub>\n- Hub:    python scripts/hub_pair_device.py --action approve --request <file>\n- Device: python scripts/hub_pair_device.py --action import --cert <file> --apply-host --apply-port\n\nHinweis:\n- Network Policy muss Hub-Host/Port erlauben.\n- Hub verlangt Token + Access Guard Cert fuer Endpunkte (ausser /health).", "U) HUB\n\nPurpose:\n- Multi-device hub with Access Guard certificates.\n\nStart server:\n- hub (CLI) or python scripts/chappie_hub.py\n\nClient examples:\n- python scripts/hub_client.py --action status --host <hub> --token <token> --cert <cert>\n- python scripts/hub_client.py --action jobs --limit 50\n- python scripts/hub_client.py --action run --execute -- --pipeline-source data/\n\nPairing (file-based):\n- Device: python scripts/hub_pair_device.py --action request --hub-host <hub>\n- Hub:    python scripts/hub_pair_device.py --action approve --request <file>\n- Device: python scripts/hub_pair_device.py --action import --cert <file> --apply-host --apply-port\n\nNotes:\n- Network policy must allow hub host/port.\n- Hub requires token + Access Guard cert for endpoints (except /health)."),
    ("D", "memory", ("mem",), "D) MEMORY\n\nZweck:\n- Einblick in gespeicherte Memory-Records.\n\nBeispiele:\n- python scripts/run_chappie.py --mode memory-stats\n- python scripts/run_chappie.py --mode memory-query --memory-text \"Jetson\"\n- python scripts/run_chappie.py --mode memory-query --memory-level ltm --memory-show-content\n\nHinweis:\n- Persistence wird ueber config.memory_policy gesteuert.\n\nFuer LLMs:\n- Stelle eine konkrete Suchanfrage (kurze Keywords).\n- Gib an, ob LTM oder alle Level relevant sind.", "D) MEMORY\n\nPurpose:\n- Inspect stored memory records.\n\nExamples:\n- python scripts/run_chappie.py --mode memory-stats\n- python scripts/run_chappie.py --mode memory-query --memory-text \"Jetson\"\n- python scripts/run_chappie.py --mode memory-query --memory-level ltm --memory-show-content\n\nNote:\n- Persistence is controlled by config.memory_policy.\n\nFor LLMs:\n- Use short, specific search keywords.\n- Specify whether LTM-only or all levels are relevant."),
    ("E", "artifacts", ("artifact", "outputs"), "E) ARTIFACTS\n\nZweck:\n- Ergebnisse finden, die Chappie erzeugt hat.\n\nBeispiele:\n- python scripts/run_chappie.py --mode artifacts\n- python scripts/run_chappie.py --mode artifacts --artifact-type rkc_curation_report\n- python scripts/run_chappie.py --mode audit-bundle --audit-bundle-run-id <run_id>\n- python scripts/dataset_explorer.py --run-id <run_id>\n\nVersionen:\n- storage/artifacts/workflow_versions.json\n\nFuer LLMs:\n- Frag nach dem Artefakt-Typ und dem Ursprung (workflow id).\n- Dann filtere gezielt mit --artifact-type/--artifact-source.", "E) ARTIFACTS\n\nPurpose:\n- Locate outputs generated by Chappie.\n\nExamples:\n- python scripts/run_chappie.py --mode artifacts\n- python scripts/run_chappie.py --mode artifacts --artifact-type rkc_curation_report\n- python scripts/run_chappie.py --mode audit-bundle --audit-bundle-run-id <run_id>\n- python scripts/dataset_explorer.py --run-id <run_id>\n\nVersions:\n- storage/artifacts/workflow_versions.json\n\nFor LLMs:\n- Ask for artifact type and source (workflow id).\n- Filter with --artifact-type/--artifact-source."),
    ("F", "assistant", ("wizard", "guide"), "F) ASSISTANT\n\nZweck:\n- Ein Wizard fuehrt dich durch Datenkuration.\n\nStarten:\n- Im CLI: assistant\n- Direkt: python scripts/chappie_assistant.py\n\nTypische Nutzung:\n- Downloads kuratieren\n- OCR/Transkription aktivieren\n\nWizard-Extras:\n- Empfehlungen aus Selfdiagnostics\n- Hilfe-Texte fuer komplexe Optionen\n\nFuer LLMs:\n- Wenn ein Nutzer 'mach das fuer mich' sagt,\n  schlage den Assistant-Wizard vor.", "F) ASSISTANT\n\nPurpose:\n- Wizard that guides data curation.\n\nStart:\n- In CLI: assistant\n- Direct: python scripts/chappie_assistant.py\n\nTypical usage:\n- Curate Downloads\n- Enable OCR/transcription\n\nWizard extras:\n- Recommendations from self diagnostics\n- Help texts for complex options\n\nFor LLMs:\n- If the user says 'do it for me',\n  suggest the assistant wizard."),
    ("R", "harvest", ("harvest_wizard", "harvest-wizard", "ernte"), "R) HARVEST\n\nZweck:\n- Neue Inhalte automatisch suchen, laden und kuratieren.\n- Themenmix + Keywords definieren.\n- Optional RKC Gate fuer Teaching-Units.\n\nStarten:\n- Im CLI: R oder harvest\n\nVoraussetzungen:\n- Search Provider (SearxNG, DuckDuckGo, qBittorrent, Archie, FTP-Auto, FTP, Veronica oder Gopher).\n- Access Guard fragt Passphrase.\n\nOutputs:\n- storage/pipelines/<run_id>/\n\nTipp:\n- Kombiniere Oberthemen + Unterthemen (z.B. LLM + Jetson + ASR).", "R) HARVEST\n\nPurpose:\n- Automatically search, download, and curate new sources.\n- Define topic mixes + keywords.\n- Optional RKC gate for teaching units.\n\nStart:\n- In CLI: R or harvest\n\nPrerequisites:\n- Search provider (SearxNG, DuckDuckGo, qBittorrent, Archie, FTP-Auto, FTP, Veronica, or Gopher).\n- Access guard prompts for passphrase.\n\nOutputs:\n- storage/pipelines/<run_id>/\n\nTip:\n- Mix broad + narrow terms (e.g. LLM + Jetson + ASR)."),
    ("G", "builder", ("assistant-builder", "spec"), "G) BUILDER\n\nZweck:\n- JSON-Specs steuern eine komplette Builder-Pipeline.\n\nBeispiele:\n- python scripts/assistant_builder.py --spec assistants/assistant_builder/assistant_spec.json --print-summary\n- Loop: python scripts/assistant_builder.py --spec assistants/assistant_builder/assistant_spec.json --iterations 3 --sleep 60\n- python scripts/run_chappie.py --mode assistant-builder --assistant-spec assistants/assistant_builder/assistant_spec.json\n\nOutputs:\n- Pipeline-Summary und Registry-Updates\n\nFuer LLMs:\n- Wenn ein fester Prozess benoetigt wird,\n  baue eine Spec statt ad-hoc Aufrufe.", "G) BUILDER\n\nPurpose:\n- JSON specs drive a full assistant builder pipeline.\n\nExamples:\n- python scripts/assistant_builder.py --spec assistants/assistant_builder/assistant_spec.json --print-summary\n- Loop: python scripts/assistant_builder.py --spec assistants/assistant_builder/assistant_spec.json --iterations 3 --sleep 60\n- python scripts/run_chappie.py --mode assistant-builder --assistant-spec assistants/assistant_builder/assistant_spec.json\n\nOutputs:\n- Pipeline summary and registry updates\n\nFor LLMs:\n- If you need a repeatable process,\n  build a spec instead of ad-hoc calls."),
    ("H", "settings", ("prefs", "config"), "H) SETTINGS\n\nZweck:\n- Systemweite Grundeinstellungen verwalten.\n\nStarten:\n- Im CLI: settings (oder s)\n\nBasis-Optionen:\n- Verhalten: Sprache, Modellsprachen, Auto-Boost, Reasoning-Mode\n- Faehigkeiten: Orchestrator, Memory-Summary, Tool-Calls, History-Limit\n- Features: Internet-Suche, Search Provider, Auto-Start, LLM Doctor\n- Runs/Workflows: Default-Profile fuer Workflow/Pipeline Runs\n- UI: Sidebar-Modus (inline/sidecar/off) + Sidebar-State-Pfad\n- Sidecar-Viewer: scripts/sidebar_viewer.py [--gui] (tmux: scripts/run_chappie_tmux.py)\n- Advanced Mode: schaltet erweiterte Optionen frei\n\nDatei:\n- storage/settings.json\n\nFuer LLMs:\n- Wenn Nutzer eine Sprache will, zuerst settings anpassen.", "H) SETTINGS\n\nPurpose:\n- Manage system-wide base settings.\n\nStart:\n- In CLI: settings (or s)\n\nBasic options:\n- Behavior: language, model languages, auto-boost, reasoning mode\n- Capabilities: orchestrator, memory summary, tool calls, history limit\n- Features: internet search, search provider, auto-start, LLM doctor\n- Runs/Workflows: default profiles for workflow/pipeline runs\n- UI: sidebar mode (inline/sidecar/off) + sidebar state path\n- Sidecar viewer: scripts/sidebar_viewer.py [--gui] (tmux: scripts/run_chappie_tmux.py)\n- Advanced mode: enables advanced options\n\nFile:\n- storage/settings.json\n\nFor LLMs:\n- If user wants a language change, update settings first."),
    ("I", "mistral", ("copilot", "llm"), "I) MISTRAL\n\nZweck:\n- Erklaert Befehle, fasst Ziele zusammen, hilft beim Planen.\n\nStarten:\n- Im CLI: mistral (oder m)\n\nVoraussetzung:\n- LLM-Config muss gesetzt sein (transformers oder llama_cpp).\n\nHinweis:\n- Mistral ist ein optionaler Copilot. Chappie fuehrt weiterhin\n  nur explizite Nutzerauftraege aus.\n\nFuer LLMs:\n- Nutze Mistral als Erklaerer und Prompt-Refiner.", "I) MISTRAL\n\nPurpose:\n- Explains commands, summarizes goals, helps planning.\n\nStart:\n- In CLI: mistral (or m)\n\nRequirement:\n- LLM config must be set (transformers or llama_cpp).\n\nNote:\n- Mistral is an optional copilot. Chappie still executes\n  only explicit user instructions.\n\nFor LLMs:\n- Use Mistral for explanations and prompt refinement."),
    ("J", "docs", ("readme", "documentation"), "J) DOCS\n\nZweck:\n- Tiefergehende Informationen nachlesen.\n\nWichtige Dateien:\n- README.md\n- BENUTZER_DOKUMENTATION.md\n- ENTWICKLER_DOKUMENTATION.md\n- KB refresh: python scripts/kb_refresh.py --docs --code\n\nFuer LLMs:\n- Verweise bei Detailfragen auf die Doku-Dateien.", "J) DOCS\n\nPurpose:\n- Read deeper documentation.\n\nKey files:\n- README.md\n- BENUTZER_DOKUMENTATION.md\n- ENTWICKLER_DOKUMENTATION.md\n- KB refresh: python scripts/kb_refresh.py --docs --code\n\nFor LLMs:\n- Point detailed questions to the docs."),
    ("K", "boost", ("booster", "augment"), "K) BOOST\n\nZweck:\n- Staerkt LLM-Schwaechen wie Kontext-Limit, Vergessen,\n  Halluzinationen oder veraltete Infos.\n\nWie es funktioniert:\n1) Prompt analysieren (optional mit Mistral).\n2) Kontext aus Memory, Systeminfo, Dateien, Artefakten, RKC sammeln.\n3) Optional Web-Suche via SearxNG (wenn konfiguriert).\n4) Ergebnis als 'boosted_prompt' ausgeben.\n\nStart:\n- Im CLI: boost\n\nBeispiel:\n- boost \"Wie installiere ich X auf Ubuntu?\"\n\nAuto-Boost:\n- settings -> Auto Boost aktivieren (optional LLM-Antwort)\n\nFallback-Modell:\n- settings.json: boost_llm_strategy + boost_llm_model_id\n\nBoost-Answer (CLI):\n- python scripts/run_chappie.py --mode boost --boost-prompt \"...\" --boost-answer\n- Mit Tools: --boost-use-tools\n- GPU-Limit: --boost-max-gpu-memory 5\n- Token-Limit: --boost-answer-max-tokens 128\n- Prompt-Limit: --boost-answer-max-chars 1200\n\nHinweis:\n- Web-Suche ist optional und erfordert SearxNG.\n  Searx-URL in settings setzen (Advanced Mode).", "K) BOOST\n\nPurpose:\n- Strengthen LLM weaknesses like context limits, forgetting,\n  hallucinations, or outdated information.\n\nHow it works:\n1) Analyze the prompt (optional with Mistral).\n2) Gather context from memory, system info, files, artifacts, RKC.\n3) Optional web search via SearxNG (if configured).\n4) Output a 'boosted_prompt'.\n\nStart:\n- In CLI: boost\n\nExample:\n- boost \"How do I install X on Ubuntu?\"\n\nAuto-boost:\n- settings -> enable Auto Boost (optional LLM answer)\n\nFallback model:\n- settings.json: boost_llm_strategy + boost_llm_model_id\n\nBoost answer (CLI):\n- python scripts/run_chappie.py --mode boost --boost-prompt \"...\" --boost-answer\n- With tools: --boost-use-tools\n- GPU limit: --boost-max-gpu-memory 5\n- Token limit: --boost-answer-max-tokens 128\n- Prompt limit: --boost-answer-max-chars 1200\n\nNote:\n- Web search is optional and requires SearxNG.\n  Set the Searx URL in settings (Advanced Mode)."),
    ("L", "llm", ("front", "llm_front", "chat"), "L) LLM-FRONT\n\nZweck:\n- Ein LLM hilft beim Verstehen der Anfrage und erstellt\n  bessere Prompts (Auto-Boost ist aktiv).\n\nStatus:\n- Deaktiviert (Policy).\n\nStart:\n- aktuell gesperrt, siehe Settings llm_front_enabled.\n\nKommandos im LLM-Front:\n- quit_llm: zur CLI zurueck\n- quit: Shutdown-Sequence starten\n- settings: Einstellungsmenue\n- help: Kurzuebersicht (beendet LLM-Front)\n- gibber on/off: LLM-zu-LLM Austausch aktivieren\n- gibber talk <prompt>: 2-Schritt Austausch\n- orchestrate on/off: Tool-Calls mit Bestaetigung\n- tools: verfuegbare Tools anzeigen\n\nMemory:\n- Optional wird eine kurze Session-Zusammenfassung\n  ins Memory geschrieben (Settings).\n\nHinweis:\n- 'quit_llm' zeigt das Hauptmenue.", "L) LLM-FRONT\n\nPurpose:\n- An LLM helps interpret the request and crafts\n  better prompts (auto-boost is active).\n\nStatus:\n- Disabled by policy.\n\nStart:\n- currently locked, see settings llm_front_enabled.\n\nCommands in LLM front:\n- quit_llm: return to CLI\n- quit: start shutdown sequence\n- settings: open settings menu\n- help: quick overview (exits LLM front)\n- gibber on/off: enable LLM-to-LLM exchange\n- gibber talk <prompt>: 2-step exchange\n- orchestrate on/off: tool calls with confirmation\n- tools: list available tools\n\nMemory:\n- Optionally a short session summary is stored\n  in memory (settings).\n\nNote:\n- 'quit_llm' shows the main menu."),
    ("M", "mistral", ("copilot", "assist"), "M) MISTRAL\n\nZweck:\n- Erklaert Konzepte, faehrt keine Aktionen aus.\n\nStart:\n- mistral (oder m)\n\nDownload (lokal):\n- python scripts/mistral_download.py --model mistral-7b-instruct --set-config\n\nBeenden:\n- back\n\nHinweis:\n- Auto-Start kann im Settings-Advanced aktiviert werden.", "M) MISTRAL\n\nPurpose:\n- Explains concepts, does not execute actions.\n\nStart:\n- mistral (or m)\n\nDownload (local):\n- python scripts/mistral_download.py --model mistral-7b-instruct --set-config\n\nExit:\n- back\n\nNote:\n- Auto-start can be enabled in settings (advanced)."),
    ("N", "kb-refresh", ("kb", "kb_refresh", "knowledge", "knowledge-base"), "N) KB REFRESH\n\nZweck:\n- Baut die deterministische Knowledge Base fuer Docs + Code neu.\n\nStart:\n- Im CLI: kb\n- Script: python scripts/kb_refresh.py --docs --code\n\nOutputs:\n- storage/llm/knowledge_base.jsonl\n- storage/llm/knowledge_base_code.jsonl", "N) KB REFRESH\n\nPurpose:\n- Rebuild the deterministic knowledge base for docs + code.\n\nRun:\n- In CLI: kb\n- Script: python scripts/kb_refresh.py --docs --code\n\nOutputs:\n- storage/llm/knowledge_base.jsonl\n- storage/llm/knowledge_base_code.jsonl"),
    ("P", "preset", ("profile", "mode"), "P) PRESET\n\nZweck:\n- Schnell zwischen Mensch/LLM/ausgewogen wechseln.\n\nBeispiele:\n- preset list\n- preset human\n- preset llm\n- preset balanced\n\nEffekt:\n- Stellt Auto-Boost/CLI-Ausgabe/Wizard-Hilfen passend ein.\n- Speichert das Preset in settings.json (ui_preset).\n\nTipp:\n- Danach mit settings feinjustieren.", "P) PRESET\n\nPurpose:\n- Switch quickly between human/LLM/balanced.\n\nExamples:\n- preset list\n- preset human\n- preset llm\n- preset balanced\n\nEffect:\n- Tunes auto-boost / CLI output / wizard hints.\n- Stores the preset in settings.json (ui_preset).\n\nTip:\n- Fine-tune afterwards via settings."),
    ("T", "todo", ("to-do", "todo-list"), "T) TODO RUNNER\n\nZweck:\n- Fuehrt eine Task-Liste aus einer JSON-Datei aus.\n- CPU-Tasks parallel, GPU-Tasks standardmaessig seriell.\n\nBeispiele:\n- python scripts/chappie_todo.py --plan storage/todo/pipeline_todo.json\n- python scripts/chappie_todo.py --mode max-performance\n- python scripts/chappie_todo.py --check\n- to-do (im CLI, fragt nach Vordergrund/Hintergrund)\n- todo-list (im CLI, listet Tasks)\n- todo-check (im CLI, prueft Tasks)\n\nLogs:\n- storage/todo/logs/\n- storage/todo/todo_events.jsonl", "T) TODO RUNNER\n\nPurpose:\n- Execute a task list from a JSON plan.\n- CPU tasks run in parallel, GPU tasks stay serialized by default.\n\nExamples:\n- python scripts/chappie_todo.py --plan storage/todo/pipeline_todo.json\n- python scripts/chappie_todo.py --mode max-performance\n- python scripts/chappie_todo.py --check\n- to-do (CLI shortcut, asks foreground/background)\n- todo-list (CLI shortcut, lists tasks)\n- todo-check (CLI shortcut, validates tasks)\n\nLogs:\n- storage/todo/logs/\n- storage/todo/todo_events.jsonl"),
    ("U", "training-eval", ("training_eval", "train-eval"), "U) TRAINING EVAL\n\nZweck:\n- Vergleicht training_report.json + eval_report.json zwischen Runs.\n\nStart:\n- python scripts/run_chappie.py --mode training-eval --training-eval-workspace-a <run_a> --training-eval-workspace-b <run_b>\n- python scripts/run_chappie.py --mode training-eval --training-eval-report-a <path> --training-eval-report-b <path>\n\nOptional:\n- --training-eval-strict (default)\n- --training-eval-no-strict\n- --training-eval-out <path>", "U) TRAINING EVAL\n\nPurpose:\n- Compare training_report.json + eval_report.json between runs.\n\nRun:\n- python scripts/run_chappie.py --mode training-eval --training-eval-workspace-a <run_a> --training-eval-workspace-b <run_b>\n- python scripts/run_chappie.py --mode training-eval --training-eval-report-a <path> --training-eval-report-b <path>\n\nOptional:\n- --training-eval-strict (default)\n- --training-eval-no-strict\n- --training-eval-out <path>"),
)


UNIQUE_PROBES = (
    ("A", 0),
    ("B", 1),
    ("C", 2),
    ("Y", 3),
    ("W", 4),
    ("O", 5),
    ("u", 6),
    ("D", 7),
    ("E", 8),
    ("F", 9),
    ("R", 10),
    ("G", 11),
    ("H", 12),
    ("I", 13),
    ("J", 14),
    ("K", 15),
    ("L", 16),
    ("assist", 17),
    ("N", 18),
    ("P", 19),
    ("T", 20),
    ("training-eval", 21),
)


def _expected_detail(key: str, language: str) -> str | None:
    lowered_language = language.strip().lower()
    lang = "de" if lowered_language.startswith("de") else "en"
    normalized = key.strip().lower()
    if not normalized:
        return None
    for record in EXPECTED_RECORDS:
        letter, command, aliases, german, english = record
        if normalized == letter.lower():
            return german if lang == "de" else english
        if normalized == command.lower():
            return german if lang == "de" else english
        for alias in aliases:
            if normalized == alias.lower():
                return german if lang == "de" else english
    return None


class W5S25ARChappieHelpDetailTests(unittest.TestCase):
    def _assert_exact_detail(self, result: object, expected: str) -> None:
        self.assertIs(type(result), str)
        self.assertEqual(result, expected)

    def test_all_22_records_all_aliases_and_full_payloads(self) -> None:
        for letter, command, aliases, german, english in EXPECTED_RECORDS:
            with self.subTest(letter=letter, command=command):
                for key in (letter, command, *aliases):
                    with self.subTest(key=key):
                        for language in ("de", "en"):
                            with self.subTest(language=language):
                                expected = _expected_detail(key, language)
                                result = s25ar.evaluate_chappie_help_detail(
                                    key, language
                                )
                                if expected is None:
                                    self.assertIs(result, None)
                                else:
                                    self._assert_exact_detail(result, expected)

    def test_all_record_details_are_exact_for_both_languages(self) -> None:
        for probe, index in UNIQUE_PROBES:
            german = EXPECTED_RECORDS[index][3]
            english = EXPECTED_RECORDS[index][4]
            with self.subTest(probe=probe):
                self._assert_exact_detail(
                    s25ar.evaluate_chappie_help_detail(probe, "de"),
                    german,
                )
                self._assert_exact_detail(
                    s25ar.evaluate_chappie_help_detail(probe, "en"),
                    english,
                )

    def test_per_topic_collision_priority_is_not_global(self) -> None:
        first_u = EXPECTED_RECORDS[6]
        second_u = EXPECTED_RECORDS[21]
        first_mistral = EXPECTED_RECORDS[13]
        second_mistral = EXPECTED_RECORDS[17]
        first_copilot = EXPECTED_RECORDS[13]
        second_copilot = EXPECTED_RECORDS[17]
        first_llm = EXPECTED_RECORDS[13]
        second_llm = EXPECTED_RECORDS[16]
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("u", "de"),
            first_u[3],
        )
        self.assertNotEqual(first_u[3], second_u[3])
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("mistral", "en"),
            first_mistral[4],
        )
        self.assertNotEqual(first_mistral[4], second_mistral[4])
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("copilot", "de"),
            first_copilot[3],
        )
        self.assertNotEqual(first_copilot[3], second_copilot[3])
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("llm", "en"),
            first_llm[4],
        )
        self.assertNotEqual(first_llm[4], second_llm[4])

    def test_normalization_is_strip_lower_and_language_prefix_only(self) -> None:
        a_record = EXPECTED_RECORDS[0]
        cases = (
            (" A ", " de-DE ", a_record[3]),
            ("aNaLyZe", "DE-at", a_record[3]),
            ("analysis", "en-US", a_record[4]),
            ("Ａ", "en", None),
            ("A", "ＤＥ", a_record[4]),
            ("A", "fr", a_record[4]),
            ("A", "", a_record[4]),
        )
        for key, language, expected in cases:
            with self.subTest(key=key, language=language):
                result = s25ar.evaluate_chappie_help_detail(key, language)
                if expected is None:
                    self.assertIs(result, None)
                else:
                    self._assert_exact_detail(result, expected)

    def test_whitespace_case_and_empty_key_boundaries(self) -> None:
        expected = EXPECTED_RECORDS[0][4]
        for key in ("", " ", "\t", "\n"):
            with self.subTest(key=repr(key)):
                self.assertIs(s25ar.evaluate_chappie_help_detail(key, "en"), None)
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("  ANALYZE  ", "en"),
            expected,
        )

    def test_unknown_keys_return_exact_none(self) -> None:
        for key in ("zzz", "not-a-help-topic", "zzzzzz", "de-DE"):
            with self.subTest(key=key):
                self.assertIs(s25ar.evaluate_chappie_help_detail(key, "en"), None)

    def test_command_and_alias_same_topic_are_still_resolved(self) -> None:
        record = EXPECTED_RECORDS[5]
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("connectors", "en"),
            record[4],
        )
        self._assert_exact_detail(
            s25ar.evaluate_chappie_help_detail("connector", "en"),
            record[4],
        )

    def test_repeated_calls_are_deterministic(self) -> None:
        for key, language in (("A", "de"), ("mistral", "en"), ("copilot", "de"), ("u", "en")):
            with self.subTest(key=key, language=language):
                expected = s25ar.evaluate_chappie_help_detail(key, language)
                for _ in range(6):
                    self.assertEqual(
                        s25ar.evaluate_chappie_help_detail(key, language),
                        expected,
                    )

    def test_outside_exact_str_precondition_is_not_claimed(self) -> None:
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()

