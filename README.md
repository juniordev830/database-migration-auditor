# Database Migration Auditor

Revisor estático de scripts SQL para identificar comandos destrutivos e atribuir níveis de risco. **Não se conecta ao banco nem executa migrações.** Saída JSON e código de saída 2 quando há operações de alto risco.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
python audit.py examples/migration.sql
python audit.py examples/migration.sql --format summary --fail-on medium
```

Por padrão, a CLI retorna JSON e encerra com código 2 quando encontra risco alto. `--fail-on` aceita `high`, `medium`, `low` ou `none` para definir o limiar do código de saída. `--format summary` apresenta contagens e achados em texto para leitura no terminal.

## Testes

```bash
python -m unittest discover -s tests -v
```

O GitHub Actions executa os testes automaticamente em pushes e pull requests.

## Segurança e limitações

Parser educacional que divide por `;` (não entende strings com ponto-e-vírgula, procedures, SQL dinâmico nem todos os dialetos). Não equivale a parser PostgreSQL; revisão humana é obrigatória.

## Evolução planejada

Usar AST com sqlglot ou parser PostgreSQL, simulação de migrações em banco isolado e relatórios SARIF.

---
Projeto de Engenharia de Software mantido na conta [juniordev830](https://github.com/juniordev830).


## Motor avançado de auditoria (API adicional)

A CLI original `audit.py` permanece disponível e sem mudanças. A nova
`advanced_audit.py` analisa múltiplos arquivos, com separação lexical que
reconhece comentários, literais SQL, identificadores entre aspas/colchetes,
strings PostgreSQL com delimitadores dollar-quote e blocos de comentários
aninhados. O analisador **nunca executa SQL**.

```bash
python advanced_audit.py examples/migration.sql --format json
python advanced_audit.py examples/migration.sql --format sarif --fail-on medium
python advanced_audit.py examples/migration.sql --format markdown
python advanced_audit.py examples/migration.sql --format csv --output report.csv
python advanced_audit.py migrations/V1__users.sql migrations/V2__orders.sql
python -m unittest discover -s tests -v
```

### Novas verificações

| Categoria | Exemplos | Nível típico |
| --- | --- | --- |
| Destrutiva | DROP TABLE, TRUNCATE, DROP COLUMN, VACUUM FULL | Alto |
| Mutação sem filtro | DELETE/UPDATE sem WHERE ou WHERE TRUE / 1=1 | Alto |
| Integridade | NOT NULL sem DEFAULT, MERGE sem ON | Alto |
| Permissões | GRANT ALL, REVOKE | Alto / médio |
| Bloqueios | CREATE INDEX sem CONCURRENTLY, LOCK TABLE | Médio |
| Alterações | ALTER TABLE, RENAME, DROP INDEX, CREATE EXTENSION | Médio |
| Criação | CREATE TABLE, CREATE SCHEMA, CREATE INDEX CONCURRENTLY | Baixo |
| Plano | Versões repetidas, ordem incorreta, CREATE TABLE duplicado | Alto / médio |

O analisador usa o local real do início de cada instrução nas saídas JSON e
SARIF. Os literais são ocultados nos trechos de SQL dos relatórios para reduzir
a exposição de dados sensíveis. CSV protege células iniciadas por caracteres
de fórmula de planilha. A API Python oferece `split_statements`,
`audit_sql`, `audit_plan`, `to_sarif`, `to_json`, `to_csv` e
`to_markdown`.

A CLI aceita `--fail-on high|medium|low|none`, `--no-order-check`,
`--max-file-bytes` e `--output`. O padrão limita cada arquivo a 2 MB e
retorna código 2 se encontrar risco alto; erros de entrada também retornam 2.
O relatório SARIF pode ser armazenado como artefato de CI ou integrado a
uma etapa de análise de código.

### Limites e precauções

- Trata-se de um **analisador lexical e heurístico**, não de parser completo
  para PostgreSQL, MySQL, SQL Server ou outros dialetos.
- Não interpreta SQL dinâmico, branches de procedimentos, dependências de
  tabelas, estatísticas do banco, planos de execução ou locks reais.
- A análise de plano verifica padrões de nomes de migração (Flyway ou prefixo
  numérico), versões duplicadas e recriações de tabelas entre arquivos.
  Isso não substitui um catálogo real nem o histórico do banco.
- Um resultado de risco baixo **não autoriza execução em produção**.
  Faça backup, revisão humana, ensaios em staging e plano de rollback.
- Scripts com aspas ou comentários malformados geram achado alto, em vez de
  tentar executar ou corrigir o SQL automaticamente.
- Não carregue migrações de origem não confiável sem isolamento apropriado;
  embora não execute SQL, o processo lê arquivos locais.

## Guia para contribuir

Veja o [roteiro de testes e manutenção](docs/GUIA_DE_VALIDACAO.md) para validar mudanças com comandos e cenários específicos deste projeto.
