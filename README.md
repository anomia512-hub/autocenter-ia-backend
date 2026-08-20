# Backend inicial do AutoCenter IA

API de preparação para conta e licença do AutoCenter IA. O projeto foi criado para conectar o aplicativo a um servidor seguro sem colocar segredos dentro do APK.

## O que já funciona

- criação de conta por e-mail com desafio de confirmação;
- sessão Bearer com token aleatório armazenado somente por hash;
- consulta do estado da licença;
- ativação com validação explicitamente bloqueada até a integração oficial da Google Play;
- modo de teste opcional (`AUTOCHECK_PLAY_VALIDATION=stub`) que aceita somente tokens começando por `TEST_`;
- regra de uma licença por conta, instalação e impressão digital da placa;
- solicitação controlada de troca de veículo;
- exclusão lógica da conta e revogação das sessões;
- banco SQLite local para desenvolvimento, substituível por PostgreSQL na publicação.

## Rodar localmente

```bash
cd autocheck_backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export AUTOCHECK_AUTH_SECRET="um-segredo-longo-e-aleatorio"
export AUTOCHECK_DEV_AUTH=true
uvicorn app:app --reload --port 8080
```

A documentação interativa fica em `http://127.0.0.1:8080/docs`.

## Fluxo de teste local

1. `POST /v1/accounts` com `{"email":"teste@exemplo.com"}`.
2. Em modo de desenvolvimento, copie o `dev_code` retornado.
3. `POST /v1/sessions` com `email`, `challenge_id` e `code`.
4. Use `Authorization: Bearer <access_token>`.
5. Consulte `GET /v1/licenses/current`.
6. Para testar ativação, defina `AUTOCHECK_PLAY_VALIDATION=stub` e use um `purchase_token` que comece com `TEST_`.

## Preparação para hospedagem

- `Dockerfile` permite executar a API em um serviço compatível com contêineres.
- `render.yaml` descreve um serviço web de teste e mantém o segredo como variável protegida.
- O plano gratuito/efêmero não deve ser usado para dados reais: SQLite precisa ser substituído por PostgreSQL persistente antes de produção.

## Antes de produção

- Trocar o envio de desafio local por provedor de e-mail/OTP.
- Integrar a API oficial de validação de compras da Google Play no servidor.
- Usar PostgreSQL, migrações e backup criptografado.
- Configurar HTTPS, domínio, rate limit, monitoramento e rotação de segredo.
- Adicionar recuperação de conta, refresh token rotativo e painel de análise de troca de veículo.
- Fazer revisão de segurança, LGPD, política de privacidade e Data Safety.
- Só então apontar o aplicativo Android para a URL pública da API.

O backend não deve ser publicado como se estivesse pronto para cobrança: a validação da Google Play está propositalmente bloqueada por padrão.
