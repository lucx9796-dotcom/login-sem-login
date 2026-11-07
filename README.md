# HybridLogin

Plugin de login híbrido para servidores Paper **1.21.11** em `online-mode=false`.

- **Original**: nick de conta original + verificação na Mojang → entra direto, sem login, com o UUID oficial (playerdata original).
- **Pirata**: nick sem conta original → precisa de `/register` e `/login`, com UUID offline (playerdata separada).
- Nick de conta original sem prova → kick (ninguém se passa por outro).
- O plugin não altera a playerdata (sem efeitos, teleporte ou invulnerabilidade); apenas bloqueia ações por evento até o login.

> ⚠️ Status: experimental. Ainda não foi testado em um servidor real. A verificação de contas originais usa reflexão em classes internas do Paper (`PremiumVerifier`) e pode precisar de ajustes.

## Requisitos
- Paper 1.21.11, Java 21
- [ProtocolLib](https://github.com/dmulloy2/ProtocolLib) 5.4.0 ou mais novo (para 1.21.9+ use a versão mais recente / build de desenvolvimento)
- `server.properties`: `online-mode=false` e `enforce-secure-profile=false`

## Build
```
mvn package
```
O jar sai em `target/HybridLogin.jar`. Coloque em `plugins/`.

## Comandos
| Comando | Descrição |
|---|---|
| `/register <senha> <repetir>` | Registra a senha (pirata) |
| `/login <senha>` | Entra no servidor (pirata) |
| `/changepassword <atual> <nova>` | Troca a senha |

Configurações e mensagens em `plugins/HybridLogin/config.yml`.
