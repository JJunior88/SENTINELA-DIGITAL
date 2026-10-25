# SENTINELA-DIGITAL

Aplicação web em português para registrar auditorias, acompanhar incidentes e organizar planos de recuperação. Inclui indicadores, busca, filtros, prioridades e atualização de status, com persistência SQLite.

Também permite revisar metadados do Google Drive com autorização OAuth e
consultar/iniciar uma varredura rápida do Microsoft Defender no PC Windows.

## Executar

### Windows, sem instalar Python

Abra [Actions → Aplicativo Windows](https://github.com/JJunior88/SENTINELA-DIGITAL/actions/workflows/windows.yml),
selecione uma execução concluída com sucesso da branch `codex/sentinela-github-tests`
e baixe **SentinelaDigital-Windows** em **Artifacts** (requer login no GitHub).
Extraia o ZIP e abra **SentinelaDigital.exe**. O navegador abre automaticamente;
feche a janela do programa para encerrar. É uma versão portátil para Windows
10/11 x64. Consulte `LEIA-ME-WINDOWS.txt` para dados e backup.

O workflow gera o pacote e testa o próprio executável antes de oferecer o download.
Os artefatos expiram em 30 dias; um novo push gera outro pacote.

### Executar pelo código-fonte

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

## Google e Drive

Na seção **Verificação de segurança**, selecione o JSON de um cliente OAuth
do tipo **Aplicativo para computador** e clique em **Conectar Google**.
O login acontece em `accounts.google.com`; nunca digite sua senha no Sentinela.
Depois do consentimento, a revisão do Drive começa automaticamente.

Para preparar o JSON, o responsável pelo aplicativo precisa:

1. Criar um projeto no [Google Cloud Console](https://console.cloud.google.com/).
2. Ativar a **Google Drive API**.
3. Configurar o Google Auth Platform (tela de consentimento), adicionar o escopo
   `https://www.googleapis.com/auth/drive.metadata.readonly` e, no modo de testes,
   incluir o e-mail que utilizará o programa nos usuários de teste.
4. Criar um cliente OAuth de **Aplicativo para computador**, baixar seu JSON
   e selecioná-lo no programa local. Não adicione esse arquivo ao Git.

A distribuição pública pode exigir verificação e outras condições do Google.
Sem esse cadastro OAuth, não é possível autorizar a conta apenas informando
seu e-mail. O JSON deve ser fornecido no programa, nunca no chat.

A conexão usa PKCE, `state` de uso único com validade de 10 minutos e retorno
HTTP na interface de loopback. Configuração OAuth e tokens ficam apenas na
memória; fechar o programa exige nova autorização. Não são solicitados tokens
de atualização. Desconectar apaga o acesso local; para revogar a autorização
no Google, use [Conexões](https://myaccount.google.com/connections).

A revisão lê até 1.000 arquivos não excluídos, ordenados por alteração mais
recente. Identifica extensões executáveis/macros e o indicador de compartilhamento.
Compartilhado não significa público. Não lê conteúdo, não baixa, modifica ou
exclui arquivos; não detecta malware. Resultados parciais são indicados.
Os relatórios ficam apenas na memória desta execução.

Não há API de conta pessoal para consultar senha, autenticação em duas etapas
e todas as sessões da conta. Para essa revisão, o programa oferece o link para
o [check-up oficial do Google](https://myaccount.google.com/security-checkup).

## Microsoft Defender

No aplicativo Windows, use **Consultar proteção** ou **Iniciar varredura rápida**.
A varredura exige confirmação porque o próprio Defender pode aplicar as ações
de proteção configuradas, inclusive quarentena. O programa não altera as opções
do antivírus. O Windows pode exigir permissões adicionais; se houver bloqueio,
consulte a Segurança do Windows e as políticas do computador.

São exibidos o estado de proteção, as datas das assinaturas e da última varredura
rápida e até 20 detecções do histórico. O histórico pode incluir ameaças anteriores;
ausência de detecções não garante ausência de malware. A varredura rápida não
verifica todos os arquivos. Em caso de timeout, a varredura pode continuar no
Windows: confira o aplicativo Segurança do Windows. Não há teste real de antivírus
nas máquinas de CI; as chamadas do Defender são simuladas nos testes automatizados.
O login real no Google também exige validação manual com uma conta autorizada.

Esta versão é destinada ao uso local por uma pessoa. Não possui login local,
controle de acesso entre usuários ou trilha de auditoria; não a exponha à internet.
Auditorias e planos de gestão continuam manuais. Não restaura arquivos.
Para backup dos registros, pare o servidor e copie o banco SQLite.
