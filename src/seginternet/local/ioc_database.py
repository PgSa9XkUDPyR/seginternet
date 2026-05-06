"""Base de dados de Indicadores de Comprometimento (IoCs) — uso defensivo."""

from __future__ import annotations

# Nomes de processos maliciosos conhecidos (RATs, keyloggers, trojans, miners)
KNOWN_MALICIOUS_PROCESS_NAMES: frozenset[str] = frozenset({
    # Remote Access Trojans
    "njrat.exe", "njw0rm.exe", "darkcomet.exe",
    "nanocore.exe", "asyncrat.exe", "async.exe",
    "remcos.exe", "remcostrap.exe", "quasar.exe",
    "xrat.exe", "xtreme.exe", "cybergate.exe", "blackshades.exe",
    "bifrost.exe", "poison.exe", "bandook.exe",
    "netbus.exe", "sub7.exe", "prorat.exe",
    "havoc.exe", "sliverserver.exe", "covenant.exe",
    # Keyloggers
    "ardamax.exe", "revealer.exe", "spyrix.exe", "kgb.exe",
    "refog.exe", "kidlogger.exe",
    # Cryptocurrency miners (não-autorizados)
    "xmrig.exe", "minerd.exe", "cpuminer.exe", "ccminer.exe",
    "cgminer.exe", "sgminer.exe", "nheqminer.exe",
    # Executáveis que imitam processos legítimos
    "svch0st.exe", "svchost32.exe", "svchost64.exe",
    "1svchost.exe", "csrss32.exe", "lsass32.exe",
    "explorer32.exe", "explorer64.exe",
    "rundll.exe",        # legítimo é rundll32.exe
    "wuauclt32.exe",
    "msconfig32.exe", "regedit32.exe",
})

# Processos legítimos do Windows e seus diretórios esperados
SYSTEM_PROCESS_EXPECTED_PATHS: dict[str, str] = {
    "svchost.exe":      r"c:\windows\system32",
    "explorer.exe":     r"c:\windows",
    "lsass.exe":        r"c:\windows\system32",
    "services.exe":     r"c:\windows\system32",
    "winlogon.exe":     r"c:\windows\system32",
    "csrss.exe":        r"c:\windows\system32",
    "smss.exe":         r"c:\windows\system32",
    "wininit.exe":      r"c:\windows\system32",
    "taskhostw.exe":    r"c:\windows\system32",
    "spoolsv.exe":      r"c:\windows\system32",
    "dwm.exe":          r"c:\windows\system32",
    "conhost.exe":      r"c:\windows\system32",
    "dllhost.exe":      r"c:\windows\system32",
    "rundll32.exe":     r"c:\windows\system32",
    "regsvr32.exe":     r"c:\windows\system32",
    "msiexec.exe":      r"c:\windows\system32",
    "cmd.exe":          r"c:\windows\system32",
    "powershell.exe":   r"c:\windows\system32\windowspowershell",
}

# Substrings de caminhos suspeitos para executáveis
SUSPICIOUS_PATH_SUBSTRINGS: tuple[str, ...] = (
    r"\temp\\",
    r"/tmp/",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"c:\windows\temp",
    r"c:\users\public",
    r"\$recycle",
    r"\recycle.bin",
    r"\programdata\\",
    r"\users\all users\\",
)

# Chaves de registro de persistência — (hive_constant, key_path)
# Hives: 0x80000002 = HKLM, 0x80000001 = HKCU
REGISTRY_AUTORUN_KEYS: tuple[tuple[int, str], ...] = (
    (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (0x80000002, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (0x80000002, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (0x80000002, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
)

HIVE_NAMES: dict[int, str] = {
    0x80000000: "HKCR",
    0x80000001: "HKCU",
    0x80000002: "HKLM",
    0x80000003: "HKU",
    0x80000005: "HKCC",
}

# Portas TCP/UDP usadas por RATs e backdoors conhecidos
SUSPICIOUS_RAT_PORTS: dict[int, str] = {
    1243:  "Sub-7 RAT",
    2745:  "Bagle Worm C2",
    4444:  "Metasploit/Meterpreter padrão",
    6666:  "Backdoor IRC",
    6667:  "Backdoor IRC",
    7777:  "God Message RAT",
    8787:  "Back Orifice 2k",
    9999:  "Aladino RAT",
    12345: "NetBus RAT",
    12346: "NetBus 2 RAT",
    20034: "NetBus Pro",
    27374: "Sub-7 RAT",
    31337: "Back Orifice",
    31338: "Back Orifice 2000",
    54321: "SchoolBus",
    65000: "Devil RAT",
}

# Portas de rede Tor (suspeito em ambientes corporativos)
TOR_PORTS: frozenset[int] = frozenset({9001, 9030, 9050, 9051, 9150})

# Extensões de script usadas em phishing e malwares
SUSPICIOUS_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({
    ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".hta", ".scr", ".pif", ".cpl", ".inf",
})
