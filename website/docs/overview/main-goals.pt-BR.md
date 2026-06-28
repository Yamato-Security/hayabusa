# Principais Objetivos

## Caça a Ameaças e DFIR em Toda a Empresa

Atualmente o Hayabusa possui mais de 4000 regras Sigma e mais de 170 regras de detecção integradas do Hayabusa, com novas regras sendo adicionadas regularmente.
Ele pode ser usado para caça proativa a ameaças em toda a empresa, bem como para DFIR (Digital Forensics and Incident Response) gratuitamente com o [artefato Hayabusa](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) do [Velociraptor](https://docs.velociraptor.app/).
Ao combinar essas duas ferramentas de código aberto, você pode essencialmente reproduzir retroativamente um SIEM quando não há nenhuma configuração de SIEM no ambiente.
Você pode aprender como fazer isso assistindo ao tutorial do Velociraptor de [Eric Capuano](https://twitter.com/eric_capuano) [aqui](https://www.youtube.com/watch?v=Q1IoGX--814).

## Geração Rápida de Linha do Tempo Forense

A análise de registros de eventos do Windows tem sido tradicionalmente um processo muito longo e tedioso porque os registros de eventos do Windows estão 1) em um formato de dados difícil de analisar e 2) a maioria dos dados é ruído e não é útil para investigações.
O objetivo do Hayabusa é extrair apenas os dados úteis e apresentá-los em um formato o mais conciso e fácil de ler possível, utilizável não apenas por analistas treinados profissionalmente, mas por qualquer administrador de sistemas Windows.
O Hayabusa espera permitir que os analistas concluam 80% de seu trabalho em 20% do tempo quando comparado à análise tradicional de registros de eventos do Windows.

![Linha do Tempo DFIR](../assets/doc/DFIR-TimelineCreation-EN.png)
