# Database Migration Auditor

Revisor estático de scripts SQL para identificar comandos destrutivos e atribuir níveis de risco. **Não se conecta ao banco nem executa migrações.** Saída JSON e código de saída 2 quando há operações de alto risco.

## Estado

**MVP funcional / projeto inicial de portfólio.** Implementa o núcleo descrito abaixo, mas não é produto pronto para produção.

## Como executar

```bash
python audit.py examples/migration.sql
```

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
