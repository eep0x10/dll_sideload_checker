# Check-DllSideloading

Script PowerShell para analise de vulnerabilidade de **DLL Sideloading** em executaveis Windows (PE). Realiza analise estatica do binario, inspecao de runtime, classificacao de risco e, opcionalmente, gera e valida uma DLL proxy de Prova de Conceito (PoC).

> **Aviso legal:** Esta ferramenta e destinada exclusivamente a testes autorizados de seguranca, pentesting, CTF e pesquisa defensiva. Nao use em sistemas sem autorizacao explicita.

---

## O que e DLL Sideloading?

Quando um executavel Windows carrega DLLs, o sistema segue uma ordem de busca. Por padrao, o **diretorio do proprio executavel** e consultado antes de System32. Se um atacante conseguir colocar uma DLL maliciosa (com o mesmo nome de uma DLL esperada pelo app) nesse diretorio, o processo ira carregar a DLL do atacante no lugar da legitima.

Ordem de busca padrao do Windows:
```
1. Diretorio do .exe          <-- ponto de ataque
2. KnownDLLs (System32)       <-- protegido pelo kernel
3. System32 / Windows
4. CWD / PATH
```

---

## Funcionalidades

| Recurso | Descricao |
|---|---|
| Parse PE manual | Le o cabecalho PE, tabela de importacao e delay-import diretamente dos bytes do arquivo |
| Analise de protecoes | Verifica ASLR, DEP, Stack Cookie (/GS), SafeSEH e Control Flow Guard (CFG) |
| Filtragem por KnownDLLs | Consulta o registro do Windows para excluir DLLs protegidas pelo kernel |
| Classificacao de risco | Marca DLLs historicamente exploradas como risco ALTO |
| Runtime scan | Executa o alvo por 3 segundos e captura todos os modulos carregados |
| Scan interativo | Abre o alvo normalmente para que o usuario interaja, monitorando DLLs em tempo real |
| Geracao de PoC | Compila uma DLL proxy com forwarding de exports para a DLL original |
| Validacao via named event | Confirma o sideloading atraves de um evento nomeado sem spawnar processos extras |
| Suporte a compiladores | Funciona com MSVC (cl.exe) e GCC/MinGW |

---

## Requisitos

- Windows 10 / 11 (ou Windows Server 2016+)
- PowerShell 5.1 ou superior
- Para geracao de PoC: **Visual Studio** (com ferramentas C++) ou **MinGW/GCC** instalado no PATH

> O script detecta automaticamente o compilador disponivel. Sem compilador, a analise estatica e runtime ainda funcionam normalmente.

---

## Como usar

### Analise estatica basica

Analisa o executavel, lista DLLs importadas, protecoes binarias e DLLs hijackáveis. Nao executa o alvo.

```powershell
.\Check-DllSideloading.ps1 -ExePath "C:\caminho\para\app.exe"
```

### Com captura de runtime (3 segundos automaticos)

Executa o alvo por 3 segundos em background, captura todos os modulos carregados e adiciona ao relatorio.

```powershell
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan
```

### Com scan interativo

Abre o alvo normalmente. Voce interage com a aplicacao (abre menus, dialogs, funcoes) enquanto o script monitora e lista DLLs carregadas em tempo real. Ao fim do tempo, o processo e encerrado automaticamente.

```powershell
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan -ScanSeconds 60
```

### Com geracao e validacao de PoC

Apos a analise, apresenta um menu interativo para selecao da DLL alvo, compila uma DLL proxy e valida o sideloading.

```powershell
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -GeneratePoC
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -RuntimeScan -GeneratePoC
.\Check-DllSideloading.ps1 -ExePath "C:\app\target.exe" -InteractiveScan -GeneratePoC
```

---

## Parametros

| Parametro | Tipo | Obrigatorio | Descricao |
|---|---|---|---|
| `-ExePath` | String | Sim | Caminho completo para o executavel analisado |
| `-RuntimeScan` | Switch | Nao | Executa o alvo por 3s e captura DLLs carregadas |
| `-InteractiveScan` | Switch | Nao | Abre o alvo para interacao manual, monitorando DLLs em tempo real |
| `-ScanSeconds` | Int | Nao | Duracao do scan interativo em segundos (padrao: 30) |
| `-GeneratePoC` | Switch | Nao | Gera e valida DLL proxy de PoC |

---

## Como funciona por dentro

### 1. Parse PE manual

O script le o arquivo em bytes e navega pelas estruturas do formato PE sem depender de ferramentas externas:

- Localiza o offset do cabecalho PE via campo `e_lfanew` (offset `0x3C`)
- Le `Machine`, `NumberOfSections`, `OptionalHeader.Magic` (PE32 vs PE32+) e `DllCharacteristics`
- Converte RVAs (enderecos virtuais relativos) para offsets de arquivo usando a tabela de secoes
- Extrai nomes de DLLs da **Import Directory Table** (entry 1 do Data Directory)
- Extrai nomes de DLLs da **Delay Import Directory Table** (entry 13 do Data Directory)

### 2. Verificacao de protecoes binarias

Lidas diretamente do campo `DllCharacteristics` do Optional Header:

| Flag | Bit | Protecao |
|---|---|---|
| DYNAMIC_BASE | `0x0040` | ASLR |
| NX_COMPAT | `0x0100` | DEP |
| NO_SEH | `0x0400` | Desabilita SEH |
| CFG | `0x4000` | Control Flow Guard |

Stack Cookie (`/GS`) e SafeSEH sao verificados via Load Configuration Directory (entry 10).

### 3. Filtragem KnownDLLs

Consulta a chave de registro:
```
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
```
DLLs listadas ali sao sempre carregadas direto do System32 pelo kernel, tornando o sideloading impossivel para elas. O script as remove da lista de candidatos.

### 4. Classificacao de risco

DLLs historicamente exploradas em ataques reais recebem classificacao **ALTO**:

```
VERSION.dll, MSIMG32.dll, NETAPI32.dll, WININET.dll, PSAPI.DLL,
IPHLPAPI.DLL, WINTRUST.dll, credui.dll, WTSAPI32.dll, COMCTL32.dll,
WSOCK32.dll, USERENV.dll, CRYPT32.dll, imagehlp.dll
```

Demais DLLs fora do KnownDLLs recebem classificacao **MEDIO**.

### 5. Monitoramento de runtime

Usa P/Invoke para chamar `EnumProcessModulesEx` (psapi.dll) com a flag `LIST_MODULES_ALL`, enumerando modulos de 32 e 64 bits do processo alvo sem necessidade de ferramentas externas.

- **RuntimeScan**: executa em background (janela minimizada), faz polling a cada 300ms por 3 segundos e encerra o processo.
- **InteractiveScan**: abre normalmente, faz polling a cada 500ms, exibe novas DLLs em tempo real no console e encerra ao fim do tempo configurado.

### 6. Geracao da DLL proxy (PoC)

Para cada DLL candidata selecionada:

1. **Extrai exports** da DLL original em System32 via parse manual da Export Directory Table
2. **Gera codigo C** com `#pragma comment(linker, "/export:FuncName=_orig_dll.FuncName")` para cada export, garantindo que o app continue funcionando normalmente (DLL proxy transparente)
3. **Payload**: uma thread separada abre um evento nomeado (criado antes do teste) e o sinaliza apos 300ms
4. **Compila** em diretorio temporario (`%TEMP%`) com MSVC ou GCC
5. **Implanta**: copia a DLL compilada para o diretorio do exe e a DLL original renomeada como `_orig_<nome>.dll`

### 7. Validacao via named event

O metodo de validacao e projetado para minimizar artefatos:

```
Script                          DLL Proxy
  |                                 |
  |-- cria evento nomeado           |
  |-- inicia alvo (minimizado)      |
  |                                 |-- DLL_PROCESS_ATTACH disparado
  |                                 |-- cria thread separada
  |                                 |-- OpenEventA(nome)
  |                                 |-- SetEvent()
  |<-- WaitOne(10s) -------------- |
  |
  resultado: sinalizado = VULNERAVEL
```

Sem spawnar `cmd.exe`, `powershell.exe` ou qualquer outro processo filho visivel.

---

## Exemplo de saida

```
  ╔══════════════════════════════════════════════════════════════╗
  ║       DLL Sideloading Analyzer  +  PoC Generator            ║
  ╚══════════════════════════════════════════════════════════════╝

  ┌─ ALVO
  │      Arquivo      : target.exe
  │      Tamanho      : 4821.3 KB
  │      Arquitetura  : PE32 (x86)
  │      Privilegio   : asInvoker
  │      Assinatura   : Valid

  ┌─ PROTECOES BINARIAS
  │  [+] ASLR (DYNAMIC_BASE)
  │  [-] DEP desabilitado
  │  [-] Stack Cookie ausente
  │  [-] SafeSEH ausente
  │  [-] CFG ausente

  ┌─ ANALISE — DLL SIDELOADING
  │  [!] 6 DLL(s) fora de KnownDLLs — hijackaveis via app directory:

     #   DLL                        Tipo             Risco    Nota
  ────   ────────────────────────   ──────────────   ──────   ────────────────────
     1   VERSION.dll                Static Import    ALTO     Comumente explorada
     2   MSIMG32.dll                Static Import    ALTO     Comumente explorada
     3   UxTheme.dll                Static Import    MEDIO
```

---

## Limpeza apos o teste

Apos validar o PoC, o script exibe os comandos exatos para remover os arquivos implantados:

```powershell
Remove-Item "C:\app\VERSION.dll"
Remove-Item "C:\app\_orig_VERSION.dll"
```

---

## Limitacoes conhecidas

- A compilacao da DLL proxy sempre gera um binario **x86 (32-bit)**, independente da arquitetura do alvo. Adequado para a maioria dos casos de sideloading em aplicativos legados.
- Antiviruses podem bloquear a DLL gerada ou impedir o carregamento, resultando em falso negativo na validacao.
- DLLs carregadas exclusivamente por plugins ou extensoes do app podem nao aparecer sem o scan interativo com interacao do usuario.
- O script requer permissao de escrita no diretorio do executavel alvo para implantar a PoC.

---

## Licenca

MIT License. Veja [LICENSE](LICENSE) para detalhes.
