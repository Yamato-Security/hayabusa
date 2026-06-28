# Recursos descontinuados

As palavras-chave especiais descontinuadas e a agregação `count` ainda são suportadas no Hayabusa, mas não serão mais usadas dentro das regras no futuro.

## Palavras-chave especiais descontinuadas

Atualmente, as seguintes palavras-chave especiais podem ser especificadas:
- `value`: corresponde por string (curingas e pipes também podem ser especificados).
- `min_length`: corresponde quando o número de caracteres é maior ou igual ao número especificado.
- `regexes`: corresponde se uma das expressões regulares no arquivo que você especificar neste campo corresponder.
- `allowlist`: a regra será ignorada se houver qualquer correspondência encontrada na lista de expressões regulares no arquivo que você especificar neste campo.

No exemplo abaixo, a regra corresponderá se o seguinte for verdadeiro:
- `ServiceName` é chamado de `malicious-service` ou contém uma expressão regular em `./rules/config/regex/detectlist_suspicous_services.txt`.
- `ImagePath` tem no mínimo 1000 caracteres.
- `ImagePath` não tem nenhuma correspondência na `allowlist`.

```yaml
detection:
    selection:
        Channel: System
        EventID: 7045
        ServiceName:
            - value: malicious-service
            - regexes: ./rules/config/regex/detectlist_suspicous_services.txt
        ImagePath:
            min_length: 1000
            allowlist: ./rules/config/regex/allowlist_legitimate_services.txt
    condition: selection
```

### Arquivos de exemplo das palavras-chave regexes e allowlist

O Hayabusa tinha dois arquivos de expressões regulares integrados usados para o arquivo `./rules/hayabusa/default/alerts/System/7045_CreateOrModiftySystemProcess-WindowsService_MaliciousServiceInstalled.yml`:
- `./rules/config/regex/detectlist_suspicous_services.txt`: para detectar nomes de serviços suspeitos
- `./rules/config/regex/allowlist_legitimate_services.txt`: para permitir serviços legítimos

Os arquivos definidos em `regexes` e `allowlist` podem ser editados para alterar o comportamento de todas as regras que os referenciam, sem precisar alterar nenhum arquivo de regra em si.

Você também pode usar diferentes arquivos de texto de detectlist e allowlist que você criar.

## Condições de agregação descontinuadas (regras `count`)

Isso ainda é suportado no Hayabusa, mas será substituído pelas regras de correlação do Sigma no futuro.

### Conceitos básicos

A palavra-chave `condition` descrita acima implementa não apenas a lógica `AND` e `OR`, mas também é capaz de contar ou "agregar" eventos.
Essa função é chamada de "condição de agregação" e é especificada conectando uma condição com um pipe.
Neste exemplo de detecção de password spray abaixo, uma expressão condicional é usada para determinar se há 5 ou mais valores de `TargetUserName` de um único `IpAddress` de origem dentro de um período de 5 minutos.

```yaml
detection:
  selection:
    Channel: Security
    EventID: 4648
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 5m
```

As condições de agregação podem ser definidas no seguinte formato:
- `count() {operator} {number}`: para eventos de log que correspondem à primeira condição antes do pipe, a condição corresponderá se o número de logs correspondentes satisfizer a expressão condicional especificada por `{operator}` e `{number}`.

`{operator}` pode ser um dos seguintes:
- `==`: se o valor for igual ao valor especificado, é tratado como correspondendo à condição.
- `>=`: se o valor for maior ou igual ao valor especificado, a condição é considerada atendida.
- `>`: se o valor for maior que o valor especificado, a condição é considerada atendida.
- `<=`: se o valor for menor ou igual ao valor especificado, a condição é considerada atendida.
- `<`: se o valor for menor que o valor especificado, será tratado como se a condição fosse atendida.

`{number}` deve ser um número.

`timeframe` pode ser definido da seguinte forma:
- `15s`: 15 segundos
- `30m`: 30 minutos
- `12h`: 12 horas
- `7d`: 7 dias
- `3M`: 3 meses

### Quatro padrões para condições de agregação

1. Nenhum argumento de count ou palavra-chave `by`. Exemplo: `selection | count() > 10`
   > Se `selection` corresponder mais de 10 vezes dentro do período de tempo, a condição corresponderá.
   > Estas são substituídas por regras de correlação Event Count que não usam o campo `group-by`.
2. Nenhum argumento de count, mas há uma palavra-chave `by`. Exemplo: `selection | count() by IpAddress > 10`
   > `selection` terá que ser verdadeiro mais de 10 vezes para o **mesmo** `IpAddress`.
   > Estas regras do tipo nº 2 são mais comuns do que as regras do tipo nº 1.
   > Você também pode especificar vários campos para agrupar. Por exemplo: `by IpAddress, Computer`
   > Estas são substituídas por regras de correlação Event Count que usam o campo `group-by`.
3. Há um argumento de count, mas nenhuma palavra-chave `by`. Exemplo: `selection | count(TargetUserName) > 10`
   > Se `selection` corresponder e `TargetUserName` for **diferente** mais de 10 vezes dentro do período de tempo, a condição corresponderá.
   > Estas são substituídas por regras de correlação Value Count que não usam o campo `group-by`.
4. Há tanto um argumento de count quanto uma palavra-chave `by`. Exemplo: `selection | count(Users) by IpAddress > 10`
   > Para o **mesmo** `IpAddress`, será necessário haver mais de 10 `TargetUserName` **diferentes** para que a condição corresponda.
   > Estas regras do tipo nº 4 são mais comuns do que as regras do tipo nº 3.
   > Estas são substituídas por regras de correlação Value Count que usam o campo `group-by`.

### Exemplo do Padrão 1

Este é o padrão mais básico: `count() {operator} {number}`. A regra abaixo corresponderá se `selection` ocorrer 3 ou mais vezes.

![](../assets/rules-doc/CountRulePattern-1-EN.png)

### Exemplo do Padrão 2

`count() by {eventkey} {operator} {number}`: os eventos de log que correspondem à `condition` antes do pipe são agrupados pelo **mesmo** `{eventkey}`. Se o número de eventos correspondentes para cada agrupamento satisfizer a condição especificada por `{operator}` e `{number}`, então a condição corresponderá.

![](../assets/rules-doc/CountRulePattern-2-EN.png)

### Exemplo do Padrão 3

`count({eventkey}) {operator} {number}`: conta quantos valores **diferentes** de `{eventkey}` existem no evento de log que correspondem à condição antes do pipe da condição. Se o número satisfizer a expressão condicional especificada em `{operator}` e `{number}`, a condição é considerada atendida.

![](../assets/rules-doc/CountRulePattern-3-EN.png)

### Exemplo do Padrão 4

`count({eventkey_1}) by {eventkey_2} {operator} {number}`: os logs que correspondem à condição antes do pipe da condição são agrupados pelo **mesmo** `{eventkey_2}`, e o número de valores **diferentes** de `{eventkey_1}` em cada grupo é contado. Se os valores contados para cada agrupamento satisfizerem a expressão condicional especificada por `{operator}` e `{number}`, a condição corresponderá.

![](../assets/rules-doc/CountRulePattern-4-EN.png)

### Saída de regras count

A saída de detalhes para regras count é fixa e imprimirá a condição count original em `[condition]` seguida pelas eventkeys registradas em `[result]`.

No exemplo abaixo, uma lista de nomes de usuário `TargetUserName` que estavam sendo alvo de bruteforce seguida pelo `IpAddress` de origem:

```
[condition] count(TargetUserName) by IpAddress >= 5 in timeframe [result] count:41 TargetUserName:jorchilles/jlake/cspizor/lpesce/bgalbraith/jkulikowski/baker/eskoudis/dpendolino/sarmstrong/lschifano/drook/rbowes/ebooth/melliott/econrad/sanson/dmashburn/bking/mdouglas/cragoso/psmith/bhostetler/zmathis/thessman/kperryman/cmoody/cdavis/cfleener/gsalinas/wstrzelec/jwright/edygert/ssims/jleytevidal/celgee/Administrator/mtoussain/smisenar/tbennett/bgreenwood IpAddress:10.10.2.22 timeframe:5m
```

O timestamp do alerta será o horário do primeiro evento detectado.
