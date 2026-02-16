import "pe"

//  Suspicious Executable Detection Rules 
// used for Flagging files that are (or contain) Windows executables.

rule SuspiciousExecutable {
    meta:
        description = "Detects suspicious executable patterns"
        author = "Threat Check"
        severity = "medium"
    strings:
        $mz = "MZ"  // DOS header signature — marks the start of a Windows executable
        $pe = "PE"  // PE header signature — found in Windows Portable Executable files
    condition:
        $mz at 0 and $pe  // File starts with 'MZ' and contains 'PE' — identifies a PE file
}

// Script-based Threat Detection Rules 
//used for JavaScript, Python, PHP, or mixed text with suspicious patterns.
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
}

// Office Document with Macros 
//used for Catching macro-bearing Office docs.
rule MacroDocument {
    meta:
        description = "Detects Office documents with macros"
        author = "Threat Check"
        severity = "low"
    strings:
        $macro1 = "VBAProject" nocase   // Marker for embedded VBA code
        $macro2 = "MacroModule" nocase  // Common in macro-enabled docs
        $macro3 = "AutoOpen" nocase     // Triggers code execution on open
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE file header (used by .doc/.xls)
    condition:
        $ole at 0 and any of ($macro*)  // OLE doc with at least one macro indicator
}

// PHP Webshell Detection 
// used for Spotting malicious PHP backdoors.
rule PHPWebshell {
    meta:
        description = "Detects common PHP webshell patterns"
        author = "Threat Check"
        severity = "high"
    strings:
        $php = "<?php"                // PHP code start tag
        $eval = "eval("               // Code execution
        $system = "system("           // System command execution
        $exec = "exec("               // Another system execution call
        $shell = "shell_exec("        // Executes shell commands
        $base64 = "base64_decode("    // Often used to decode obfuscated payloads
    condition:
        $php and 2 of ($eval, $system, $exec, $shell, $base64)
        // Detects PHP scripts executing or decoding code (common in webshells)
}

// SQL Injection Pattern Detection 
//used for Identifying potential SQL injection attempts.
rule SQLInjectionPattern {
    meta:
        description = "Detects potential SQL injection patterns in files"
        author = "Threat Check"
        severity = "medium"
    strings:
        $sql1 = /union\s+select/ nocase   // Typical SQLi join payload
        $sql2 = /'\s*or\s*'1'\s*=\s*'1/ nocase
        $sql3 = /'\s*or\s*1\s*=\s*1/ nocase
        $sql4 = "xp_cmdshell" nocase      // Dangerous SQL Server command execution
    condition:
        any of them  // Match any known SQLi signature
}

//Suspicious Batch File 
//used for Flagging potentially malicious batch scripts.
rule SuspiciousBatchScript {
    meta:
        description = "Detects potentially malicious batch scripts"
        author = "Threat Check"
        severity = "medium"
    strings:
        $echo_off = "@echo off" nocase     // Common in batch scripts
        $del = /del\s+\/f\s+\/q/ nocase    // Forced file deletion
        $reg = "reg add" nocase            // Registry modification
        $schtasks = "schtasks" nocase      // Task scheduling persistence
        $download = /(powershell|curl|wget).*http/ nocase  // Downloading via batch
    condition:
        $echo_off and 2 of ($del, $reg, $schtasks, $download)
        // Flags scripts that combine stealth with system manipulation
}

// Obfuscated JavaScript 
//used for Detecting obfuscated JavaScript code.
rule ObfuscatedJavaScript {
    meta:
        description = "Detects obfuscated JavaScript code"
        author = "Threat Check"
        severity = "medium"
    strings:
        $eval = "eval("                  // Dynamic code execution
        $unescape = "unescape("          // String de-obfuscation
        $fromcharcode = "fromCharCode("  // String reconstruction from char codes
        $hex = /\\x[0-9a-f]{2}/ nocase   // Hexadecimal-encoded strings
    condition:
        2 of them  // Detects scripts using multiple obfuscation techniques
}

// Ransomware Note Indicators
// used for Identifying potential ransomware note patterns.
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
        3 of them  // Detects ransom notes mentioning encryption and payment
}

//Suspicious PowerShell Commands
//used for Detecting suspicious PowerShell command patterns.
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
        // Detects PowerShell used stealthily or for downloading payloads
}

//Suspicious API Imports in Executables
// used for Flagging PEs importing runtime APIs often used in attacks.
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
        // Flags executables importing APIs commonly used in process injection or code loading
}

//Network Indicator Detection
//used for Detecting suspicious URLs, IP:port combinations, or unusual domains.
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
        // Detects suspicious URLs, hardcoded IP:ports, or unusual C2 domains
}

// Suspicious VBA in Office Docs
//used for Detecting Office documents embedding suspicious VBA code.
rule EmbeddedSuspiciousVBA {
    meta:
        description = "Office doc embedding suspicious VBA calls"
        author = "Threat Check"
        severity = "high"
    strings:
        $vba = "VBAProject" nocase
        $createobject = "CreateObject(" nocase     // Used to instantiate COM objects
        $shell = "WScript.Shell" nocase            // Used to execute commands
        $download = "URLDownloadToFile" nocase     // Downloading external payloads
    condition:
        $vba and 2 of ($createobject, $shell, $download)
        // Detects malicious macros creating shell objects or downloading files
}
