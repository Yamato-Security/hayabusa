# Regras do Hayabusa

As regras de detecção do Hayabusa são escritas em um formato YML semelhante ao do Sigma e estão localizadas na pasta `rules`.
As regras estão hospedadas em [https://github.com/Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules), portanto, envie quaisquer issues e pull requests referentes às regras para lá, em vez de para o repositório principal do Hayabusa.

Consulte [Criando Arquivos de Regras](creating-rules.md), [Campos de Detecção](detection-fields.md) e [Correlações Sigma](correlations.md) nesta seção para entender o formato das regras e como criá-las. (Fonte: o [repositório hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).)

Todas as regras do repositório hayabusa-rules devem ser colocadas na pasta `rules`.
Regras de nível `informational` são consideradas `events`, enquanto qualquer regra com um `level` de `low` ou superior é considerada `alerts`.

A estrutura de diretórios das regras do Hayabusa é separada em 2 diretórios:

* `builtin`: logs que podem ser gerados pela funcionalidade interna do Windows.
* `sysmon`: logs que são gerados pelo [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

As regras são ainda separadas em diretórios por tipo de log (Exemplo: Security, System, etc...) e são nomeadas no seguinte formato:

Confira as regras atuais para usá-las como modelo na criação de novas regras ou para verificar a lógica de detecção.

## Regras Sigma v.s. Hayabusa (Compatíveis com Sigma Integrado)

O Hayabusa oferece suporte nativo a regras Sigma, com uma única exceção: o tratamento dos campos `logsource` internamente.
Para reduzir falsos positivos, as regras Sigma devem ser processadas pelo nosso conversor explicado [aqui](https://github.com/Yamato-Security/hayabusa-rules/blob/main/tools/sigmac/README.md).
Isso adicionará o `Channel` e o `EventID` apropriados e realizará o mapeamento de campos para determinadas categorias, como `process_creation`.

Quase todas as regras do Hayabusa são compatíveis com o formato Sigma, então você pode usá-las assim como as regras Sigma para converter para outros formatos de SIEM.
As regras do Hayabusa são projetadas exclusivamente para análise de logs de eventos do Windows e oferecem os seguintes benefícios:

1. Um campo `details` adicional para exibir informações complementares extraídas apenas dos campos úteis do log.
2. Todas são testadas contra logs de amostra e sabe-se que funcionam.
3. Agregadores extras não encontrados no Sigma, como `|equalsfield` e `|endswithfield`.

Até onde sabemos, o Hayabusa oferece o maior suporte nativo a regras Sigma dentre todas as ferramentas de análise de logs de eventos do Windows de código aberto.
