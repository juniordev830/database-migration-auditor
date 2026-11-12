# Guia de validação — Database Migration Auditor

## Estado e abrangência

Ferramenta Python de análise estática de SQL que não executa scripts no banco.

## Fontes para revisão

`audit.py`, `advanced_audit.py`, `sql_lexer.py`, `sql_risk_engine.py`, `migration_plan.py` e testes.

## Comandos de verificação

`python -m unittest discover -s tests -v`; `python audit.py examples/migration.sql --format summary --fail-on medium`.

Os testes automatizados devem ser revisados junto do código. Caso não tenham sido executados, registrar essa limitação no PR.

## Matriz de regressão

Testar comentários e strings contendo palavras SQL destrutivas, quoting, instruções multiline, falso positivo e código de saída para high/medium.

## Próximo incremento fundamentado

Não tratar análise textual como aprovação de migração produtiva. Adicionar casos reais anonimizados por dialeto sem conexão com banco.

## Critérios de contribuição

- [ ] Alteração atende comportamento verificável.
- [ ] Foi criada evidência de teste ou procedimento reproduzível.
- [ ] Nenhuma credencial ou dado pessoal foi versionado.
- [ ] O PR identifica claramente o que mudou e o que ainda falta.
