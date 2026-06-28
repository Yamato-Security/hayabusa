# Executando o Hayabusa

## Atenção: Avisos de Antivírus/EDR e Tempos de Execução Lentos

Você pode receber um alerta de produtos antivírus ou EDR ao tentar executar o hayabusa ou até mesmo apenas ao baixar as regras `.yml`, pois haverá palavras-chave como `mimikatz` e comandos suspeitos do PowerShell na assinatura de detecção.
Esses são falsos positivos, portanto será necessário configurar exclusões em seus produtos de segurança para permitir que o hayabusa seja executado.
Se você estiver preocupado com malware ou ataques à cadeia de suprimentos, verifique o código-fonte do hayabusa e compile os binários você mesmo.

Você pode notar um tempo de execução lento, especialmente na primeira execução após uma reinicialização, devido à proteção em tempo real do Windows Defender.
Você pode evitar isso desativando temporariamente a proteção em tempo real ou adicionando uma exclusão ao diretório de execução do hayabusa.
(Considere os riscos de segurança antes de fazer isso.)

## Windows

Em um Prompt de Comando/PowerShell ou no Windows Terminal, basta executar o binário do Windows de 32 bits ou de 64 bits apropriado.

### Erro ao tentar escanear um arquivo ou diretório com um espaço no caminho

Ao usar o Prompt de Comando ou PowerShell integrado do Windows, você pode receber um erro de que o Hayabusa não conseguiu carregar nenhum arquivo .evtx se houver um espaço no caminho do seu arquivo ou diretório.
Para carregar os arquivos .evtx corretamente, certifique-se de fazer o seguinte:
1. Coloque o caminho do arquivo ou diretório entre aspas duplas.
2. Se for um caminho de diretório, certifique-se de não incluir uma barra invertida como último caractere.

### Caracteres não sendo exibidos corretamente

Com a fonte padrão `Lucida Console` no Windows, vários caracteres usados no logotipo e nas tabelas não serão exibidos corretamente.
Você deve alterar a fonte para `Consalas` para corrigir isso.

Isso corrigirá a maior parte da renderização do texto, exceto a exibição de caracteres japoneses nas mensagens de encerramento:

![Mojibake](../assets/screenshots/Mojibake.png)

Você tem quatro opções para corrigir isso:
1. Use o [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) em vez do Prompt de Comando ou PowerShell. (Recomendado)
2. Use a fonte `MS Gothic`. Observe que as barras invertidas se transformarão em símbolos de Iene.
   ![MojibakeFix](../assets/screenshots/MojibakeFix.png)
3. Instale as fontes [HackGen](https://github.com/yuru7/HackGen/releases) e use `HackGen Console NF`.
4. Use `-q, --quiet` para não exibir as mensagens de encerramento que contêm japonês.

## Linux

Primeiro, você precisa tornar o binário executável.

```bash
chmod +x ./hayabusa
```

Em seguida, execute-o a partir do diretório raiz do Hayabusa:

```bash
./hayabusa
```

## macOS

No Terminal ou iTerm2, primeiro você precisa tornar o binário executável.

```bash
chmod +x ./hayabusa
```

Em seguida, tente executá-lo a partir do diretório raiz do Hayabusa:

```bash
./hayabusa
```

Na versão mais recente do macOS, você pode receber o seguinte erro de segurança ao tentar executá-lo:

![Mac Error 1 EN](../assets/screenshots/MacOS-RunError-1-EN.png)

Clique em "Cancel" e, em seguida, nas Preferências do Sistema, abra "Security & Privacy" e, na guia General, clique em "Allow Anyway".

![Mac Error 2 EN](../assets/screenshots/MacOS-RunError-2-EN.png)

Depois disso, tente executá-lo novamente.

```bash
./hayabusa
```

O seguinte aviso aparecerá, então clique em "Open".

![Mac Error 3 EN](../assets/screenshots/MacOS-RunError-3-EN.png)

Agora você deve conseguir executar o hayabusa.
