# Saída da Linha do Tempo

## Perfis de Saída

O Hayabusa possui 5 perfis de saída predefinidos para usar em `config/profiles.yaml`:

1. `minimal`
2. `standard` (padrão)
3. `verbose`
4. `all-field-info`
5. `all-field-info-verbose`
6. `super-verbose`
7. `timesketch-minimal`
8. `timesketch-verbose`

Você pode personalizar facilmente ou adicionar seus próprios perfis editando este arquivo.
Você também pode alterar facilmente o perfil padrão com `set-default-profile --profile <profile>`.
Use o comando `list-profiles` para mostrar os perfis disponíveis e as informações de seus campos.

### 1. Saída do perfil `minimal`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%`

### 2. Saída do perfil `standard`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%`, %RuleID%

### 3. Saída do perfil `verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 4. Saída do perfil `all-field-info`

Em vez de exibir as informações mínimas de `details`, todas as informações de campo nas seções `EventData` e `UserData` serão exibidas junto com seus nomes de campo originais.

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 5. Saída do perfil `all-field-info-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %RuleTitle%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### 6. Saída do perfil `super-verbose`

`%Timestamp%, %Computer%, %Channel%, %EventID%, %Level%, %RuleTitle%, %RuleAuthor%, %RuleModifiedDate%, %Status%, %RecordID%, %Details%, %ExtraFieldInfo%, %MitreTactics%, %MitreTags%, %OtherTags%, %Provider%, %RuleCreationDate%, %RuleFile%, %RuleID%, %EvtxFile%`

### 7. Saída do perfil `timesketch-minimal`

Saída em um formato compatível com a importação no [Timesketch](https://timesketch.org/).

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %RuleFile%, %RuleID%, %EvtxFile%`

### 8. Saída do perfil `timesketch-verbose`

`%Timestamp%, hayabusa, %RuleTitle%, %Computer%, %Channel%, %EventID%, %Level%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%`

### Comparação de Perfis

Os benchmarks a seguir foram realizados em um Lenovo P51 de 2018 (CPU Xeon de 4 núcleos / 64GB de RAM) com 3GB de dados evtx e 3891 regras habilitadas. (2023/06/01)

| Perfil | Tempo de Processamento | Tamanho do Arquivo de Saída | Aumento do Tamanho do Arquivo |
| :---: | :---: | :---: | :---: |
| minimal | 8 minutos 50 segundos | 770 MB | -30% |
| standard (padrão) | 9 minutos 00 segundos | 1.1 GB | Nenhum |
| verbose | 9 minutos 10 segundos | 1.3 GB | +20% |
| all-field-info | 9 minutos 3 segundos | 1.2 GB | +10% |
| all-field-info-verbose | 9 minutos 10 segundos | 1.3 GB | +20% |
| super-verbose | 9 minutos 12 segundos | 1.5 GB | +35% |

### Aliases de Campo de Perfil

As informações a seguir podem ser exibidas com os perfis de saída integrados:

| Nome do alias | Informações de saída do Hayabusa|
| :--- | :--- |
|%AllFieldInfo% | Todas as informações de campo. |
|%Channel% | O nome do log. Campo `<Event><System><Channel>`. |
|%Computer% | O campo `<Event><System><Computer>`. |
|%Details% | O campo `details` na regra de detecção YML; no entanto, apenas as regras do hayabusa possuem este campo. Este campo fornece informações extras sobre o alerta ou evento e pode extrair dados úteis dos campos nos registros de eventos. Por exemplo, nomes de usuário, informações de linha de comando, informações de processo, etc... Quando um placeholder aponta para um campo que não existe ou há um mapeamento de alias incorreto, ele será exibido como `n/a` (não disponível). Se o campo `details` não for especificado (ou seja, regras sigma), as mensagens `details` padrão para extrair os campos definidos em `./rules/config/default_details.txt` serão exibidas. Você pode adicionar mais mensagens `details` padrão adicionando o `Provider Name`, o `EventID` e a mensagem `details` que você deseja exibir em `default_details.txt`. Quando nenhum campo `details` é definido em uma regra nem em `default_details.txt`, todos os campos serão exibidos na coluna `details`. |
|%ExtraFieldInfo% | Exibe as informações de campo que não foram exibidas em %Details%. |
|%EventID% | O campo `<Event><System><EventID>`. |
|%EvtxFile% | O nome do arquivo evtx que causou o alerta ou evento. |
|%Level% | O campo `level` na regra de detecção YML. (`informational`, `low`, `medium`, `high`, `critical`) |
|%MitreTactics% | [Táticas](https://attack.mitre.org/tactics/enterprise/) do MITRE ATT&CK (Ex: Initial Access, Lateral Movement, etc...). |
|%MitreTags% | ID do Grupo, ID da Técnica e ID do Software do MITRE ATT&CK. |
|%OtherTags% | Qualquer palavra-chave no campo `tags` de uma regra de detecção YML que não esteja incluída em `MitreTactics` ou `MitreTags`. |
|%Provider% | O atributo `Name` no campo `<Event><System><Provider>`. |
|%RecordID% | O Event Record ID do campo `<Event><System><EventRecordID>`. |
|%RuleAuthor% | O campo `author` na regra de detecção YML. |
|%RuleCreationDate% | O campo `date` na regra de detecção YML. |
|%RuleFile% | O nome do arquivo da regra de detecção que gerou o alerta ou evento. |
|%RuleID% | O campo `id` na regra de detecção YML. |
|%RuleModifiedDate% | O campo `modified` na regra de detecção YML. |
|%RuleTitle% | O campo `title` na regra de detecção YML. |
|%Status% | O campo `status` na regra de detecção YML. |
|%Timestamp% | O padrão é o formato `YYYY-MM-DD HH:mm:ss.sss +hh:mm`. Campo `<Event><System><TimeCreated SystemTime>` no registro de eventos. O fuso horário padrão será o fuso horário local, mas você pode alterar o fuso horário para UTC com a opção `--utc`. |

#### Alias de Campo de Perfil Extra

Você também pode adicionar este alias extra ao seu perfil de saída, caso precise:

| Nome do alias | Informações de saída do Hayabusa|
| :--- | :--- |
|%RenderedMessage% | O campo `<Event><RenderingInfo><Message>` em logs encaminhados WEC. |

Observação: este **não** está incluído em nenhum perfil integrado, portanto, você precisará editar manualmente o arquivo `config/default_profile.yaml` e adicionar a seguinte linha:

```
Message: "%RenderedMessage%"
```

Você também pode definir [aliases de chave de evento](https://github.com/Yamato-Security/hayabusa-rules/blob/main/README.md#eventkey-aliases) para exibir outros campos.
