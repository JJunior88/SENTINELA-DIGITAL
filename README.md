# SENTINELA-DIGITAL

Aplicação web em português para registrar auditorias, acompanhar incidentes e organizar planos de recuperação. Inclui indicadores, busca, filtros, prioridades e atualização de status, com persistência SQLite.

## Executar

Requer Python 3.12 ou superior, sem pacotes externos.

```bash
cd /workspace/SENTINELA-DIGITAL
python3 app.py
```

O servidor usa a porta 8000 e escuta apenas na interface local por padrão. `PORT`, `HOST` e `SENTINELA_DB` permitem configurar porta, interface e caminho do banco. O banco é criado automaticamente em `data/sentinela.db`; preserve esse arquivo para manter os registros.

## Testar

```bash
python3 -m unittest discover -s tests -v
```

### Testar no GitHub

O workflow **Testes do Sentinela Digital**, na aba **Actions**, executa os testes
automaticamente a cada push e pull request. Abra a execução e o passo
**Executar testes de integração** para conferir os resultados.

Também é possível iniciar manualmente em **Actions → Testes do Sentinela Digital
→ Run workflow**, quando o workflow estiver na branch padrão. Os testes verificam
a API, a página inicial, a validação de dados e a persistência após reiniciar o
servidor, usando um banco temporário. Não é necessário configurar secrets.

O GitHub Actions executa os testes automatizados; ele não hospeda a interface
interativa da aplicação.

Esta versão é destinada ao uso local por uma pessoa. Não possui autenticação, controle de acesso ou trilha de auditoria; não a exponha à internet. Auditorias e planos são registros manuais: o sistema não executa scanners nem restaura arquivos. Para backup, pare o servidor e copie o banco SQLite.
