## Regras de Contagem de Eventos

Estas são regras que contam determinados eventos e alertam se ocorrerem muitos ou poucos desses eventos dentro de um intervalo de tempo.
Exemplos comuns de detecção de muitos eventos dentro de um determinado período de tempo são para detectar ataques de adivinhação de senha, ataques de pulverização de senha e ataques de negação de serviço.
Você também pode usar essas regras para detectar problemas de confiabilidade da fonte de log, como quando determinados eventos ficam abaixo de um certo limite.

### Exemplo de regra de Contagem de Eventos:

O exemplo a seguir usa duas regras para detectar ataques de adivinhação de senha.
Haverá um alerta quando a regra referenciada corresponder 5 ou mais vezes dentro de 5 minutos e o campo `IpAddress` for o mesmo para esses eventos.

> Observe que incluímos apenas os campos necessários para entender o conceito.
> A regra completa na qual este exemplo se baseia está localizada [aqui](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml) para sua referência.

### Regra de correlação de Contagem de Eventos:

```yaml
title: PW Guessing
id: 23179f25-6fce-4827-bae1-b219deaf563e
correlation:
    type: event_count
    rules:
        - 5b0b75dc-9190-4047-b9a8-14164cee8a31
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 5
```

### Regra de Falha de Logon - Senha Incorreta:

```yaml
title: Failed Logon - Incorrect Password
id: 5b0b75dc-9190-4047-b9a8-14164cee8a31
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter
```

### Exemplo de regra `count` obsoleta:

A correlação acima e as regras referenciadas fornecem os mesmos resultados que a regra a seguir, que usa o modificador `count` mais antigo:

```yaml
title: PW Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc000006a" #Wrong password
    filter:
       IpAddress: "-"
    condition: selection and not filter | count() by IpAddress >= 5
    timeframe: 5m
```
### Saída da regra de Contagem de Eventos:

As regras acima criarão a seguinte saída:
```
% ./hayabusa csv-timeline -d ../hayabusa-sample-evtx -r password-guessing-sample.yml -w
% 
Timestamp · RuleTitle · Level · Computer · Channel · EventID · RecordID · Details · ExtraFieldInfo
2016-09-20 01:50:06.513 +09:00 · PW Guessing · med · DESKTOP-M5SN04R · Sec · 4625 · - · Count: 3558 ¦ IpAddress: 192.168.198.149 · -
```

## Regras de Contagem de Valores

Estas regras contam os mesmos eventos dentro de um intervalo de tempo com valores **diferentes** de um determinado campo.

Exemplos:

- Varreduras de rede em que um único endereço IP de origem tenta se conectar a muitos endereços IP e/ou portas de destino diferentes.
- Ataques de pulverização de senha em que uma única origem falha em autenticar com muitos usuários diferentes.
- Detectar ferramentas como o BloodHound que enumeram muitos grupos do AD de alto privilégio em um curto intervalo de tempo.

### Exemplo de regra de Contagem de Valores:

A regra a seguir detecta quando um atacante está tentando adivinhar nomes de usuário.
Ou seja, quando o **mesmo** endereço IP de origem (`IpAddress`) falha ao fazer logon com mais de 3 nomes de usuário **diferentes** (`TargetUserName`) dentro de 5 minutos.

> Observe que incluímos apenas os campos necessários para entender o conceito.
> A regra completa na qual este exemplo se baseia está localizada [aqui](https://github.com/Yamato-Security/hayabusa-rules/tree/main/hayabusa/builtin/Security/LogonLogoff/Logon/Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml) para sua referência.

### Regra de correlação de Contagem de Valores:

```yaml
title: User Guessing
id: 0ae09af3-f30f-47c2-a31c-83e0b918eeee
correlation:
    type: value_count
    rules:
        - b2c74582-0d44-49fe-8faa-014dcdafee62
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gt: 3
        field: TargetUserName
```

### Regra de Falha de Logon de Contagem de Valores (Usuário Inexistente):

```yaml
title: Failed Logon - Non-Existant User
id: b2c74582-0d44-49fe-8faa-014dcdafee62
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection
```

### Regra do modificador `count` obsoleto:

A correlação acima e as regras referenciadas fornecem os mesmos resultados que a regra a seguir, que usa o modificador `count` mais antigo:

```
title: User Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        SubStatus: "0xc0000064" #Username does not exist
    condition: selection | count(TargetUserName) by IpAddress > 3 
    timeframe: 5m
```

### Saída da regra de Contagem de Valores:

As regras acima criarão a seguinte saída:
```
2018-08-23 23:24:22.523 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: ninja-labs/root/test@ninja-labs.com/sarutobi ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-08-28 08:03:13.770 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/sarutobi@ninja-labs.com/sarutobi/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-01 12:51:58.346 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/admin/administrator@ninja-labs.com ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -

2018-09-02 03:55:13.007 +09:00 · User Guessing · med · dmz-ftp · Sec · 4625 · - · Count: 4 ¦ TargetUserName: root/admin@ninja-labs.com/administrator@ninja-labs.com/admin ¦ IpAddress: - ¦ LogonType: 8 ¦ TargetDomainName:  ¦ ProcessName: C:\\Windows\\System32\\svchost.exe ¦ LogonProcessName: Advapi ¦ WorkstationName: DMZ-FTP · -
```

## Regras de Proximidade Temporal

Todos os eventos definidos pelas regras referidas pelo campo rule devem ocorrer no intervalo de tempo definido por timespan.
Os valores dos campos definidos em `group-by` devem ter todos o mesmo valor (ex: mesmo host, usuário, etc...).

### Exemplo de regra de Proximidade Temporal:

Exemplo: Comandos de reconhecimento definidos em três regras Sigma são invocados em ordem arbitrária dentro de 5 minutos em um sistema pelo mesmo usuário.

### Regra de correlação de Proximidade Temporal:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - Computer
        - User
    timespan: 5m
```

## Regras de Proximidade Temporal Ordenada

O tipo de correlação `temporal_ordered` se comporta como `temporal` e exige adicionalmente que os eventos apareçam na ordem fornecida no atributo `rules`.

### Exemplo de regra de Proximidade Temporal Ordenada:

Exemplo: muitos logins com falha, conforme definido acima, são seguidos por um login bem-sucedido da mesma conta de usuário dentro de 1 hora:

### Regra de correlação de Proximidade Temporal Ordenada:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

## Notas sobre regras de correlação

1. Você deve incluir todas as suas regras de correlação e regras referenciadas em um único arquivo e separá-las com um separador YAML de `---`.

2. Por padrão, as regras de correlação referenciadas não serão exibidas. Se você quiser ver a saída das regras referenciadas, então precisa adicionar `generate: true` em `correlation`. Isso é muito útil para ativar e verificar ao criar regras de correlação.

    Exemplo:
    ```
    correlation:
        generate: true
    ```
3. Você pode usar nomes de alias em vez de IDs de regra ao referenciar regras, a fim de tornar as coisas mais fáceis de entender.

4. Você pode referenciar várias regras.

5. Você pode usar vários campos em `group-by`. Se fizer isso, então todos os valores nesses campos precisam ser iguais ou você não receberá um alerta. Na maioria das vezes, você escreverá regras que filtram em determinados campos com `group-by` a fim de reduzir falsos positivos, no entanto, é possível omitir `group-by` para criar uma regra mais genérica.

6. O timestamp da regra de correlação será o exato início do ataque, então você deve verificar os eventos após esse momento para confirmar se é um falso positivo ou não.
