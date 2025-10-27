
rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious executable patterns"
        author = "Threat Check"
        severity = "medium"
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz at 0 and $pe
}

rule SuspiciousScript {
    meta:
        description = "Detects potentially malicious script patterns"
        author = "Threat Check"
        severity = "medium"
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $shell = /cmd\.exe|powershell|\/bin\/sh|\/bin\/bash/ nocase
        $encode = "base64" nocase
    condition:
        2 of them
}

rule MacroDocument {
    meta:
        description = "Detects Office documents with macros"
        author = "Threat Check"
        severity = "low"
    strings:
        $macro1 = "VBAProject" nocase
        $macro2 = "MacroModule" nocase
        $macro3 = "AutoOpen" nocase
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $ole at 0 and any of ($macro*)
}

rule PHPWebshell {
    meta:
        description = "Detects common PHP webshell patterns"
        author = "Threat Check"
        severity = "high"
    strings:
        $php = "<?php"
        $eval = "eval("
        $system = "system("
        $exec = "exec("
        $shell = "shell_exec("
        $base64 = "base64_decode("
    condition:
        $php and 2 of ($eval, $system, $exec, $shell, $base64)
}

rule SQLInjectionPattern {
    meta:
        description = "Detects potential SQL injection patterns in files"
        author = "Threat Check"
        severity = "medium"
    strings:
        $sql1 = /union\s+select/i
        $sql2 = /\'\s*or\s*\'1\'\s*=\s*\'1/i
        $sql3 = /\'\s*or\s*1\s*=\s*1/i
        $sql4 = "xp_cmdshell" nocase
    condition:
        any of them
}

rule EmbeddedExecutable {
    meta:
        description = "Detects executables embedded in documents"
        author = "Threat Check"
        severity = "high"
    strings:
        $doc_zip = { 50 4B 03 04 }  // ZIP signature (used by docx, xlsx)
        $mz = "MZ"
        $pe = "PE"
    condition:
        $doc_zip at 0 and ($mz or $pe)
}

rule SuspiciousBatchScript {
    meta:
        description = "Detects potentially malicious batch scripts"
        author = "Threat Check"
        severity = "medium"
    strings:
        $echo_off = "@echo off" nocase
        $del = /del\s+\/f\s+\/q/i
        $reg = "reg add" nocase
        $schtasks = "schtasks" nocase
        $download = /(powershell|curl|wget).*http/i
    condition:
        $echo_off and 2 of ($del, $reg, $schtasks, $download)
}

rule ObfuscatedJavaScript {
    meta:
        description = "Detects obfuscated JavaScript code"
        author = "Threat Check"
        severity = "medium"
    strings:
        $eval = "eval("
        $unescape = "unescape("
        $fromcharcode = "fromCharCode("
        $hex = /\\x[0-9a-f]{2}/i
    condition:
        2 of them
}

rule PotentialRansomwareNote {
    meta:
        description = "Detects potential ransomware note patterns"
        author = "Threat Check"
        severity = "high"
    strings:
        $ransom1 = "encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "payment" nocase
        $ransom5 = /pay.*bitcoins?/i
    condition:
        3 of them
}

rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell command patterns"
        author = "Threat Check"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $bypass = "ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $encoded = "-EncodedCommand" nocase
        $download = "DownloadString" nocase
        $webclient = "Net.WebClient" nocase
    condition:
        $ps1 and 2 of ($bypass, $hidden, $encoded, $download, $webclient)
}

rule SuspiciousPEImports {
    meta:
        description = "PEs importing suspicious runtime APIs"
        author = "Threat Check"
        severity = "high"
    condition:
        pe.number_of_imported_functions > 0 and
        (
            "VirtualAlloc" in pe.imports("kernel32.dll") or
            "VirtualProtect" in pe.imports("kernel32.dll") or
            "CreateRemoteThread" in pe.imports("kernel32.dll") or
            "LoadLibraryA" in pe.imports("kernel32.dll") or
            "GetProcAddress" in pe.imports("kernel32.dll")
        )
}

rule SuspiciousNetworkIndicators {
    meta:
        description = "Detect suspicious URLs, IP:port or obvious C2 domains"
        author = "Threat Check"
        severity = "medium"
    strings:
        $url = /(https?:\/\/)?[a-z0-9\.\-]{3,}\.(php|asp|aspx|jsp)\/[^\s'"]*/i
        $ipport = /\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?):(80|8080|8443|4444|8888)\b/
        $sld = /[a-z0-9\-]{10,}\.(com|xyz|top|site|online)/i
    condition:
        any of them
}

rule EmbeddedSuspiciousVBA {
    meta:
        description = "Office doc embedding suspicious VBA calls"
        author = "Threat Check"
        severity = "high"
    strings:
        $vba = "VBAProject" nocase
        $createobject = "CreateObject(" nocase
        $shell = "WScript.Shell" nocase
        $download = "URLDownloadToFile" nocase
    condition:
        $vba and 2 of ($createobject, $shell, $download)
}
