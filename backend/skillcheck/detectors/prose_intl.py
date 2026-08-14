"""Non-English variants of the highest-value prose rules in `prose.py`.

Every pattern in `prose.py` is English-only. A `SKILL.md` is markdown — a
*format*, not a language — so nothing about the file type stops its prose
payload from being written in Spanish, German, Russian, or Chinese, and an
attacker who wants to slip a phrase like "ignore previous instructions" past
an English-only pattern set has an easy, well-documented way to do it: say it
in a different language. That makes this the highest-value blind spot to
close in this scanner, because prose *is* the payload in a skill package —
there is no equivalent of an AST to fall back on the way `code.py` can for
Python.

This module is deliberately narrow rather than a general translation layer:
seven languages (`es`, `fr`, `de`, `pt`, `ru`, `zh`, `ja`), each covering the
same seven intents `prose.py` already covers in English — agent
manipulation (two phrasings), stage-2 fetch, exfiltration, credential
access, persistence, anti-forensics — chosen because those are exactly the
patterns SC-P1/P2/P7/P8/P9/P10/P11 already carry, so English and non-English
skills are held to a comparable bar rather than an asymmetric one. It is not
a claim of exhaustive multilingual coverage: a paraphrase this module's
translator didn't anticipate is exactly as invisible as a paraphrase
`prose.py` didn't anticipate. See docs/detection-model.md for what's still
open (more languages, more phrasings per language).

Latin-alphabet and Cyrillic languages use `\b`-bounded patterns exactly like
`prose.py` — Python's `re` treats accented Latin and Cyrillic letters as
`\w` under the default Unicode matching, so word boundaries behave the same
way they do for English. Chinese and Japanese carry no whitespace between
words, so `\b` is meaningless there (there is no non-word/word transition to
find at a phrase boundary) — those patterns match the literal phrase
directly with no boundary assertion.
"""
from __future__ import annotations

import re

from ..models import Capability, Finding, Severity

# Sink domains and credential paths are literal ASCII regardless of which
# language governs them, so they're shared across every language block
# below rather than re-typed per language.
_SINKS = r"(?:webhook\.site|pastebin\.com|discord(?:app)?\.com/api/webhooks|ngrok\.io|requestbin\.com)"
_CRED_PATHS = r"(?:\.aws/credentials|\.ssh/id_rsa|\.env\b(?!\.(?:example|sample|template|dist)\b)|\.npmrc|kube/?config|wallet\.dat|cookies?\.sqlite)"
_PERSIST_TARGET_ALTS = r"crontab|\.bashrc|\.zshrc|launchagents|systemd"
_PERSIST_TARGETS = r"(?:" + _PERSIST_TARGET_ALTS + r")"

# (rule_id, lang, capability, severity, pattern, rationale)
_PATTERNS: list[tuple[str, str, Capability, Severity, str, str]] = [
    # --- Spanish ---------------------------------------------------------
    ("SC-PI1", "es", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bignora(?:n|d)?\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)\b",
     "Spanish-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI2", "es", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bno\s+(?:le\s+)?digas\s+(?:esto\s+)?al\s+usuario\b|\bno\s+informes?\s+al\s+usuario\b",
     "Spanish-language instruction to conceal an action from the user."),
    ("SC-PI3", "es", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\bdescarga(?:r|lo)?\b.{0,30}\b(?:y|luego)\b.{0,10}\bejecuta(?:r|lo)?\b",
     "Spanish-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI4", "es", Capability.EXFILTRATION, Severity.HIGH,
     r"\benv[ií]a(?:r|lo)?\b.{0,60}\b(?:a|hacia)\b.{0,40}" + _SINKS,
     "Spanish-language instruction to send data to a known exfiltration sink."),
    ("SC-PI5", "es", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:lee|abre|copia)\b.{0,40}" + _CRED_PATHS,
     "Spanish-language instruction to read a well-known credential file path."),
    ("SC-PI6", "es", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\bagrega(?:r|lo)?\b.{0,40}\b" + _PERSIST_TARGETS + r"\b",
     "Spanish-language instruction to install a persistence mechanism."),
    ("SC-PI7", "es", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:borra|elimina)(?:r|lo)?\b.{0,30}\b(?:historial|\.bash_history|registros)\b",
     "Spanish-language instruction to clear shell history or logs."),

    # --- French ------------------------------------------------------------
    ("SC-PI8", "fr", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bignor(?:e|ez)\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)\b",
     "French-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI9", "fr", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bne\s+(?:dis|dites|r[eé]v[eè]l(?:e|ez))\s+(?:pas\s+)?(?:ceci\s+)?[aà]\s+l'?utilisateur\b",
     "French-language instruction to conceal an action from the user."),
    ("SC-PI10", "fr", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\bt[eé]l[eé]charg(?:e(?:z)?|er)\b.{0,30}\b(?:et|puis)\b.{0,10}\bex[eé]cut(?:e(?:z)?|er)\b",
     "French-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI11", "fr", Capability.EXFILTRATION, Severity.HIGH,
     # "envoyer" (infinitive) and "envoyez" are spelled with a "y" — only
     # "envoie" keeps the "i" — so this can't be one shared stem the way
     # "copie/copiez" can; the three real forms are listed directly.
     r"\benvo(?:ie|yez|yer)\b.{0,60}\b(?:[aà]|vers)\b.{0,40}" + _SINKS,
     "French-language instruction to send data to a known exfiltration sink."),
    ("SC-PI12", "fr", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:lis|lisez|ouvre|ouvrez|copie|copiez)\b.{0,40}" + _CRED_PATHS,
     "French-language instruction to read a well-known credential file path."),
    ("SC-PI13", "fr", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\bajout(?:e|ez)\b.{0,40}\b" + _PERSIST_TARGETS + r"\b",
     "French-language instruction to install a persistence mechanism."),
    ("SC-PI14", "fr", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:efface|effacez|supprime|supprimez)\b.{0,30}\b(?:historique|\.bash_history|journaux)\b",
     "French-language instruction to clear shell history or logs."),

    # --- German --------------------------------------------------------------
    ("SC-PI15", "de", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bignorier(?:e|en\s+sie)\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+anweisungen\b",
     "German-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI16", "de", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bsag(?:e)?\s+(?:es\s+)?dem\s+benutzer\s+nicht\b|\bverrate(?:n\s+sie)?\s+(?:dies\s+)?nicht\s+dem\s+benutzer\b",
     "German-language instruction to conceal an action from the user."),
    ("SC-PI17", "de", Capability.STAGE2_FETCH, Severity.HIGH,
     # German separable verbs appear two ways: split around an object in the
     # imperative ("lade die Datei herunter"), or as one compound word in
     # the infinitive ("...Datei herunterladen"). Both branches are needed —
     # the compound form is the more natural phrasing in running prose.
     r"\b(?:lade(?:n\s+sie)?\s+herunter|herunterlad(?:en|en\s+sie|et))\b"
     r".{0,20}\b(?:und|dann)\b.{0,10}"
     r"\b(?:f[uü]hre(?:n\s+sie)?\s+aus|ausf[uü]hr(?:en|en\s+sie|t))\b",
     "German-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI18", "de", Capability.EXFILTRATION, Severity.HIGH,
     r"\bsende(?:n\s+sie)?\b.{0,60}\ban\b.{0,40}" + _SINKS,
     "German-language instruction to send data to a known exfiltration sink."),
    ("SC-PI19", "de", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:lies|lesen\s+sie|[oö]ffne|[oö]ffnen\s+sie|kopiere|kopieren\s+sie)\b.{0,40}" + _CRED_PATHS,
     "German-language instruction to read a well-known credential file path."),
    ("SC-PI20", "de", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\bf[uü]ge(?:n\s+sie)?\b.{0,40}\b" + _PERSIST_TARGETS + r"\b.{0,20}\bhinzu\b",
     "German-language instruction to install a persistence mechanism."),
    ("SC-PI21", "de", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:l[oö]sche|l[oö]schen\s+sie)\b.{0,30}\b(?:verlauf|\.bash_history|protokolle)\b",
     "German-language instruction to clear shell history or logs."),

    # --- Portuguese --------------------------------------------------------
    ("SC-PI22", "pt", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bignore\s+(?:todas\s+)?as\s+instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)\b",
     "Portuguese-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI23", "pt", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bn[aã]o\s+(?:diga|informe)\s+(?:isso\s+)?ao\s+usu[aá]rio\b",
     "Portuguese-language instruction to conceal an action from the user."),
    ("SC-PI24", "pt", Capability.STAGE2_FETCH, Severity.HIGH,
     r"\bbaixe\b.{0,20}\b(?:e|depois)\b.{0,10}\bexecute\b",
     "Portuguese-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI25", "pt", Capability.EXFILTRATION, Severity.HIGH,
     r"\benvie\b.{0,60}\b(?:para|a)\b.{0,40}" + _SINKS,
     "Portuguese-language instruction to send data to a known exfiltration sink."),
    ("SC-PI26", "pt", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:leia|abra|copie)\b.{0,40}" + _CRED_PATHS,
     "Portuguese-language instruction to read a well-known credential file path."),
    ("SC-PI27", "pt", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\badicione\b.{0,40}\b" + _PERSIST_TARGETS + r"\b",
     "Portuguese-language instruction to install a persistence mechanism."),
    ("SC-PI28", "pt", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:apague|limpe)\b.{0,30}\b(?:hist[oó]rico|\.bash_history|registros)\b",
     "Portuguese-language instruction to clear shell history or logs."),

    # --- Russian -------------------------------------------------------------
    ("SC-PI29", "ru", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bигнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прошлые)\s+инструкции\b",
     "Russian-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI30", "ru", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"\bне\s+говори(?:те)?\s+пользователю\b|\bне\s+сообщай(?:те)?\s+пользователю\b",
     "Russian-language instruction to conceal an action from the user."),
    ("SC-PI31", "ru", Capability.STAGE2_FETCH, Severity.HIGH,
     # Natural phrasing more often uses "а затем" ("and then") as the
     # connector than a bare "и" ("and") — both are covered.
     r"\bскачай(?:те)?\b.{0,20}\b(?:и|затем)\b.{0,10}\bзапусти(?:те)?\b",
     "Russian-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI32", "ru", Capability.EXFILTRATION, Severity.HIGH,
     r"\bотправ(?:ь|ьте)\b.{0,60}\b(?:на|в)\b.{0,40}" + _SINKS,
     "Russian-language instruction to send data to a known exfiltration sink."),
    ("SC-PI33", "ru", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"\b(?:прочитай(?:те)?|открой(?:те)?|скопируй(?:те)?)\b.{0,40}" + _CRED_PATHS,
     "Russian-language instruction to read a well-known credential file path."),
    ("SC-PI34", "ru", Capability.PERSISTENCE, Severity.MEDIUM,
     r"\bдобав(?:ь|ьте)\b.{0,40}\b" + _PERSIST_TARGETS + r"\b",
     "Russian-language instruction to install a persistence mechanism."),
    ("SC-PI35", "ru", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"\b(?:удали(?:те)?|очисти(?:те)?)\b.{0,30}\b(?:историю|\.bash_history|логи)\b",
     "Russian-language instruction to clear shell history or logs."),

    # --- Chinese (simplified) — no \b: CJK has no whitespace word boundary ---
    ("SC-PI36", "zh", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"忽略(?:之前|以上|先前)的?(?:所有)?指(?:示|令)",
     "Chinese-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI37", "zh", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"不要(?:告诉用户|让用户知道)",
     "Chinese-language instruction to conceal an action from the user."),
    ("SC-PI38", "zh", Capability.STAGE2_FETCH, Severity.HIGH,
     # An object noun (the thing being downloaded) almost always sits
     # between the two verbs in natural phrasing — "下载安装包，然后运行" —
     # so a fixed gap is needed rather than the two verbs directly adjacent.
     r"下载.{0,20}(?:并|然后).{0,10}(?:运行|执行)",
     "Chinese-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI39", "zh", Capability.EXFILTRATION, Severity.HIGH,
     r"发送.{0,30}(?:到|至).{0,20}" + _SINKS,
     "Chinese-language instruction to send data to a known exfiltration sink."),
    ("SC-PI40", "zh", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     r"(?:读取|打开|复制).{0,20}" + _CRED_PATHS,
     "Chinese-language instruction to read a well-known credential file path."),
    ("SC-PI41", "zh", Capability.PERSISTENCE, Severity.MEDIUM,
     r"添加.{0,20}(?:" + _PERSIST_TARGET_ALTS + r")",
     "Chinese-language instruction to install a persistence mechanism."),
    ("SC-PI42", "zh", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"(?:删除|清除).{0,15}(?:历史记录|\.bash_history|日志)",
     "Chinese-language instruction to clear shell history or logs."),

    # --- Japanese — no \b, same reason as Chinese -----------------------
    ("SC-PI43", "ja", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"(?:前|これまで)の指示を無視して",
     "Japanese-language classic prompt-injection override phrase (\"ignore previous instructions\")."),
    ("SC-PI44", "ja", Capability.AGENT_MANIPULATION, Severity.HIGH,
     r"ユーザーに(?:伝えないで|知らせないで)",
     "Japanese-language instruction to conceal an action from the user."),
    ("SC-PI45", "ja", Capability.STAGE2_FETCH, Severity.HIGH,
     r"ダウンロードして(?:実行|起動)",
     "Japanese-language download-then-execute stage-2 payload phrasing."),
    ("SC-PI46", "ja", Capability.EXFILTRATION, Severity.HIGH,
     # Japanese is verb-final (SOV): natural phrasing puts the destination
     # before the verb — "webhook.site にレポートを送信" — the reverse of
     # the English/Chinese verb-first order, so both orders are matched.
     r"送信.{0,30}" + _SINKS + r"|" + _SINKS + r".{0,30}送信",
     "Japanese-language instruction to send data to a known exfiltration sink."),
    ("SC-PI47", "ja", Capability.CREDENTIAL_ACCESS, Severity.HIGH,
     # Same SOV reordering as SC-PI46: "~/.ssh/id_rsa をコピーして" puts the
     # path before the verb.
     r"(?:読み取|開いて|コピーして).{0,20}" + _CRED_PATHS +
     r"|" + _CRED_PATHS + r".{0,20}(?:読み取|開いて|コピーして)",
     "Japanese-language instruction to read a well-known credential file path."),
    ("SC-PI48", "ja", Capability.PERSISTENCE, Severity.MEDIUM,
     r"(?:" + _PERSIST_TARGET_ALTS + r").{0,10}に追加",
     "Japanese-language instruction to install a persistence mechanism."),
    ("SC-PI49", "ja", Capability.ANTI_FORENSICS, Severity.MEDIUM,
     r"(?:履歴|\.bash_history|ログ)を(?:削除|消去)",
     "Japanese-language instruction to clear shell history or logs."),
]

_COMPILED = [(rid, lang, cap, sev, re.compile(pat, re.IGNORECASE | re.DOTALL), why)
             for rid, lang, cap, sev, pat, why in _PATTERNS]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def detect_prose_intl(file_path: str, text: str, provenance: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, lang, cap, sev, rx, why in _COMPILED:
        for m in rx.finditer(text):
            start_line = _line_of(text, m.start())
            end_line = _line_of(text, m.end())
            findings.append(Finding(
                rule_id=rid,
                capability=cap,
                file=file_path,
                start_line=start_line,
                end_line=end_line,
                matched_text=m.group(0).strip()[:400],
                severity=sev,
                rationale=why,
                # A notch below prose.py's 0.55: these are single literal
                # phrasings per intent rather than an English pattern that's
                # absorbed several rounds of real-world false-positive
                # tuning, so the same confidence would overstate how well
                # this specific phrasing has been exercised.
                confidence=0.5,
                provenance=list(provenance or []) + [f"lang:{lang}"],
                detector="prose-intl",
            ))
    return findings
