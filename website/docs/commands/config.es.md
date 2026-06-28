# Comandos de configuración

## Comando `config-critical-systems`

Este comando intentará encontrar automáticamente sistemas críticos como controladores de dominio y servidores de archivos y los añadirá al archivo de configuración `./config/critical_systems.txt` para que todas las alertas se incrementen un nivel.
Buscará eventos Security 4768 (solicitud de TGT de Kerberos) para determinar si es un controlador de dominio.
Buscará eventos Security 5145 (acceso a archivos de recurso compartido de red) para determinar si es un servidor de archivos.
Cualquier nombre de host añadido al archivo `critical_systems.txt` tendrá todas las alertas por encima de low incrementadas un nivel con un máximo de nivel `emergency`.

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

### Ejemplos del comando `config-critical-systems`

* Buscar controladores de dominio y servidores de archivos en el directorio `../hayabusa-sample-evtx`:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
