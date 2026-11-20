# CODAX — Serviço de transmissão NFS-e Nacional

Serviço separado do site que assina e envia as notas à API gratuita do governo
(Ambiente de Dados Nacional da NFS-e). Ele existe porque a emissão exige uma
conexão autenticada com o certificado A1 da empresa (mTLS), que a hospedagem do
site não suporta.

## Como funciona

1. O site CODAX guarda o rascunho da nota e o certificado A1 selado (cofre criptografado).
2. Este serviço busca o rascunho e o certificado pela rota `/api/public/nfse/relay`
   do site, identificando-se com uma chave compartilhada.
3. Abre o cofre, assina a declaração (DPS) e envia ao governo com o certificado.
4. Devolve ao site o resultado: autorizada (com número), rejeitada ou erro.

Nenhum certificado ou senha fica salvo neste serviço — tudo é buscado sob demanda
e descartado após o envio.

## Publicar no Render (plano gratuito)

1. Crie uma conta em <https://render.com> (não pede cartão).
2. **New → Web Service**, conecte este repositório e escolha a pasta `nfse-relay`
   como *Root Directory*.
3. O arquivo `render.yaml` já define o plano gratuito, o build e a rota de saúde
   `/saude`.
4. Em **Environment**, cadastre as variáveis:

   | Variável | Valor |
   |---|---|
   | `CODAX_APP_URL` | endereço público do site CODAX |
   | `CODAX_RELAY_KEY` | senha longa gerada por você — a mesma cadastrada no site |
   | `CODAX_CERTIFICATE_ENCRYPTION_KEY` | mesma chave do cofre do site |
   | `NFSE_AMBIENTE` | `homologacao` nos testes; `producao` só depois de validar |

5. No site CODAX, cadastre o segredo `CODAX_RELAY_KEY` com o mesmo valor.

## Observações do plano gratuito do Render

- Sem cartão e sem cobrança.
- O serviço "dorme" após ~15 minutos sem uso; a primeira emissão depois disso
  demora ~30–60 segundos para acordar. As demais saem na hora.

## Antes de emitir notas reais

- A empresa precisa estar cadastrada no Portal Nacional da NFS-e.
- Valide uma emissão completa no ambiente de homologação (produção restrita).
- Só então mude `NFSE_AMBIENTE` para `producao`.
