/*
  ThreatCheck YARA rules

  This file contains YARA rules used to detect suspicious or potentially
  malicious files. Each rule looks for patterns linked to a certain type
  of threat, such as executables, scripts, macros, webshells, ransomware
  notes, PowerShell abuse, or suspicious network indicators.
*/

import "pe"

// Suspicious Executable Detection Rules
// Used to flag files that are, or contain, Windows executables.
rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious executable patterns"
        author = "Threat Check"
        severity = "medium"
    strings:
        $mz = "MZ"  // DOS header signature at the start of Windows executables
        $pe = "PE"  // PE header signature found in Portable Executable files
    condition:
        $mz at 0 and $pe
        // Match if the file starts with MZ and also contains PE
}

// Script-based Threat Detection Rules
// Used for JavaScript, Python, PHP, or mixed text containing suspicious behaviour.
rule SuspiciousScript
{
    meta:
        description = "Detect suspicious script patterns with weighted logic"
        severity = "medium"
    strings:
        $eval = "eval(" nocase ascii wide
        $exec = "exec(" nocase ascii wide
        $shell = /cmd\.exe|powershell|\/bin\/sh|\/bin\/bash/ nocase ascii wide
        $encode = "base64" nocase ascii wide
        $atob = "atob(" nocase ascii wide
        $fromcc = "fromCharCode(" nocase ascii wide
    condition:
        ($eval and $atob) or
        ($shell and $encode) or
        (3 of ($eval,$exec,$shell,$encode,$fromcc,$atob))
        // Match when several suspicious scripting behaviours appear together
}

// Office Document with Macros
// Used for catching macro-enabled Office documents.
rule MacroDocument {
    meta:
        description = "Detects Office documents with macros"
        author = "Threat Check"
        severity = "low"
    strings:
        $macro1 = "VBAProject" nocase
        $macro2 = "MacroModule" nocase
        $macro3 = "AutoOpen" nocase
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE file header for older Office documents
    condition:
        $ole at 0 and any of ($macro*)
        // Match if the file is an OLE document and contains macro indicators
}

// PHP Webshell Detection
// Used for spotting malicious PHP backdoors.
rule PHPWebshell {
    meta:
        description = "Detects common PHP webshell patterns"
        author = "Threat Check"
        severity = "high"
    strings:
        $php = "<?php"                // PHP code start tag
        $eval = "eval("               // Dynamic code execution
        $system = "system("           // System command execution
        $exec = "exec("               // Alternate command execution call
        $shell = "shell_exec("        // Executes shell commands
        $base64 = "base64_decode("    // Common in obfuscated PHP malware
    condition:
        $php and 2 of ($eval, $system, $exec, $shell, $base64)
        // Match PHP files that also perform suspicious execution or decoding
}

// SQL Injection Pattern Detection
// Used for identifying common SQL injection payloads inside files or text.
rule SQLInjectionPattern {
    meta:
        description = "Detects potential SQL injection patterns in files"
        author = "Threat Check"
        severity = "medium"
    strings:
        $sql1 = /union\s+select/ nocase
        $sql2 = /'\s*or\s*'1'\s*=\s*'1/ nocase
        $sql3 = /'\s*or\s*1\s*=\s*1/ nocase
        $sql4 = "xp_cmdshell" nocase
    condition:
        any of them
        // Match if any known SQL injection pattern appears
}

// Suspicious Batch File
// Used for flagging potentially malicious batch scripts.
rule SuspiciousBatchScript {
    meta:
        description = "Detects potentially malicious batch scripts"
        author = "Threat Check"
        severity = "medium"
    strings:
        $echo_off = "@echo off" nocase
        $del = /del\s+\/f\s+\/q/ nocase
        $reg = "reg add" nocase
        $schtasks = "schtasks" nocase
        $download = /(powershell|curl|wget).*http/ nocase
    condition:
        $echo_off and 2 of ($del, $reg, $schtasks, $download)
        // Match batch files that combine command execution with system changes or downloads
}

// Obfuscated JavaScript
// Used for detecting JavaScript that appears intentionally hidden or encoded.
rule ObfuscatedJavaScript {
    meta:
        description = "Detects obfuscated JavaScript code"
        author = "Threat Check"
        severity = "medium"
    strings:
        $eval = "eval("
        $unescape = "unescape("
        $fromcharcode = "fromCharCode("
        $hex = /\\x[0-9a-f]{2}/ nocase
    condition:
        2 of them
        // Match when at least two obfuscation patterns are found
}

// Ransomware Note Indicators
// Used for identifying possible ransom note text.
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
        $ransom5 = /pay.*bitcoins?/ nocase
    condition:
        3 of them
        // Match if the text strongly resembles a ransom demand
}

// Suspicious PowerShell Commands
// Used for detecting PowerShell often linked to malware delivery or stealth.
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
        // Match PowerShell commands that use stealth or download behaviour
}

// Suspicious API Imports in Executables
// Used for flagging PE files importing APIs often seen in malware techniques.
rule SuspiciousPEImports {
    meta:
        description = "PEs importing suspicious runtime APIs"
        author = "Threat Check"
        severity = "high"
    condition:
        pe.number_of_imported_functions > 0 and
        (
            pe.imports("kernel32.dll", "VirtualAlloc") or
            pe.imports("kernel32.dll", "VirtualProtect") or
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("kernel32.dll", "LoadLibraryA") or
            pe.imports("kernel32.dll", "GetProcAddress")
        )
        // Match PEs using APIs often associated with injection or dynamic loading
}

// Network Indicator Detection
// Used for detecting suspicious URLs, IP:port values, or unusual domains.
rule SuspiciousNetworkIndicators {
    meta:
        description = "Detect suspicious URLs, IP:port or obvious C2 domains"
        author = "Threat Check"
        severity = "medium"
    strings:
        $url = /(https?:\/\/)?[a-z0-9\.\-]{3,}\.(php|asp|aspx|jsp)\/[^\s'"]*/ nocase
        $ipport = /\b((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?):(80|8080|8443|4444|8888)\b/
        $sld = /[a-z0-9\-]{10,}\.(com|xyz|top|site|online)/ nocase
    condition:
        any of them
        // Match if the file contains suspicious network-related indicators
}

// Suspicious VBA in Office Docs
// Used for detecting Office documents that embed dangerous VBA behaviour.
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
        // Match documents containing VBA plus suspicious object creation or downloading
}

// Dangerous Python Dynamic Execution
// Used for detecting Python code that dynamically runs data with eval or exec.
rule DangerousPythonDynamicExecution
{
    meta:
        description = "Detects Python dynamic execution via eval/exec (often malicious, but can be abused)"
        author = "Threat Check"
        severity = "high"
    strings:
        $py_print = "print(" nocase ascii wide
        $py_eval  = "eval("  nocase ascii wide
        $py_exec  = "exec("  nocase ascii wide
        $py_data  = "data"   nocase ascii wide
    condition:
        ($py_eval and $py_exec) or
        ($py_data and $py_eval) or
        ($py_exec and $py_print)
        // Match Python files that appear to evaluate or execute dynamic content
}

// Python eval/exec demo pattern
// Used for catching demo or test scripts that use eval(data) and exec().
rule PythonEvalExecDemoPattern
{
    meta:
        description = "Flags demo/test scripts using eval(data) and exec()"
        author = "Threat Check"
        severity = "medium"
    strings:
        $assign = /data\s*=\s*["'][^"']+["']/ nocase ascii
        $evald  = "eval(data)" nocase ascii wide
        $execp  = /exec\(\s*["']print\(/ nocase ascii
    condition:
        $assign and $evald and $execp
        // Match very specific demo-style Python dynamic execution patterns
}