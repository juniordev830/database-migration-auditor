# Database Migration Auditor

Auditor **estático e somente leitura** de arquivos SQL para identificar comandos destrutivos. Nunca abre conexões nem executa migrações.

## Funcionalidades

- Classifica instruções como alto risco (ex.: `DROP TABLE`, `TRUNCATE`, `DELETE` ou `UPDATE` sem `WHERE`), baixo risco (`CREATE`) ou revisão manual.
- O scanner reconhece **strings SQL entre aspas simples**, identificadores entre aspas duplas, aspas duplicadas, comentários `--` e `/* ... */`. Assim, `';'` dentro de uma string não é tratado como separador de comandos.
- Strings e identificadores entre aspas são mascarados durante a detecção de palavras-chave: `UPDATE tabela SET descricao='WHERE'` continua sendo classificado como perigoso, pois `WHERE` aparece somente no valor de texto.
- Recusa strings, identificadores e comentários de bloco não terminados, com erro legível na CLI.
- Exporta resultados em JSON, resumo textual ou SARIF para uso em CI.

## Uso

```bash
python audit.py examples/migration.sql
python audit.py examples/migration.sql --format summary --fail-on medium
python audit.py examples/migration.sql --format sarif
python -m unittest discover -s tests -v
```

`--fail-on` aceita `high`, `medium`, `low` e `none`. O padrão é `high`; o processo termina com código 2 quando o limite configurado é atingido ou existe erro de entrada.

## Limitações importantes

O scanner **não é um parser SQL completo**: não entende todas as gramáticas e dialetos, comandos dinâmicos, funções/procedures, strings com escape `E'...'`, identificadores com crases, comentários de bloco aninhados ou blocos PostgreSQL `$$...$$`. Mesmo quando existe `WHERE`, isso não comprova que uma operação é segura. A saída SARIF é demonstrativa e ainda aponta localizações genéricas (linha 1). Não substitui revisão humana nem análise em ambiente isolado.

Os exemplos são fictícios. Licença ainda não definida.
