# Comandos de Configuração

## Comando `config-critical-systems`

Este comando tentará automaticamente encontrar sistemas críticos como controladores de domínio e servidores de arquivos e adicioná-los ao arquivo de configuração `./config/critical_systems.txt` para que todos os alertas sejam aumentados em um nível.
Ele buscará eventos Security 4768 (Kerberos TGT requested) para determinar se é um controlador de domínio.
Ele buscará eventos Security 5145 (Network Share File Access) para determinar se é um servidor de arquivos.
Quaisquer nomes de host adicionados ao arquivo `critical_systems.txt` terão todos os alertas acima de low aumentados em um nível, com um nível máximo de `emergency`.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### Exemplos do comando `config-critical-systems`

* Buscar controladores de domínio e servidores de arquivos no diretório `../hayabusa-sample-evtx`:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
