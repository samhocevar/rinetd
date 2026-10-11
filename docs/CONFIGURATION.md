# Guia de configuração — rinetd-ng 1.0 RC1

Este guia descreve os parâmetros **realmente disponíveis** no motor compatível com o rinetd 0.73, segundo `rinetd.8` e o parser `src/parse.peg` do upstream. Recursos planejados (DNS refresh automático, balanceamento, health checks, métricas e limites por IP) **não estão disponíveis** nesta RC1.

## Arquivo e validação

O arquivo padrão é `/etc/rinetd.conf`. Uma regra por linha; `#` inicia comentário. A opção de CLI `-c /caminho/arquivo` seleciona outra configuração; `-f` mantém o daemon em foreground, `-h` mostra ajuda, e `-v` mostra versão.

Para validar a sintaxe com a ferramenta fornecida no pacote, use, a partir da raiz do projeto:

```bash
./bin/rinetd-ng-config-check -c /etc/rinetd.conf
```

**Atenção:** o validador não substitui os testes operacionais nem garante que o destino é alcançável. Na RC1 o reload ainda não é transacional; uma configuração inválida pode derrubar o serviço.

## Redirecionamentos TCP e UDP

Sintaxe geral:

```text
bindaddress bindport connectaddress connectport [timeout=N,src=ENDERECO]
```

| Campo | Significado | Exemplo |
|---|---|---|
| `bindaddress` | Endereço local no qual o rinetd escuta. `0.0.0.0` abrange todas as interfaces IPv4. | `192.168.25.35` |
| `bindport` | Porta de escuta; TCP por padrão; aceita `/tcp`, `/udp` ou nome de serviço. | `18080`, `5353/udp` |
| `connectaddress` | IP ou hostname de destino; IPv4/IPv6 aceitos. | `192.168.25.10` |
| `connectport` | Porta/protocolo de destino; TCP por padrão. | `300`, `53/udp` |
| `timeout=N` | Tempo de inatividade de sessão **UDP**, em segundos. Padrão: 72 s. | `[timeout=120]` |
| `src=ENDERECO` | Endereço IP local usado como origem para conectar ao destino; deve pertencer ao host. | `[src=192.168.25.35]` |

Exemplo SSH via encaminhamento TCP:

```ini
192.168.25.35 18080 192.168.25.10 300
allow 192.168.25.*
```

Exemplo DNS via UDP:

```ini
127.0.0.1 15353/udp 192.168.25.10 53/udp [timeout=120]
allow 127.0.0.1
```

Exemplo de `src` e `timeout` juntos (parâmetros separados por vírgula):

```ini
192.168.25.35 15353/udp 192.168.25.10 53/udp [timeout=120,src=192.168.25.35]
```

**Aviso:** o rinetd 0.73 também permite encaminhamento entre UDP e TCP, mas isso não transforma protocolos aplicativos automaticamente; evite misturá-los sem conhecer o protocolo. Hostnames são resolvidos na leitura/reload da configuração, não continuamente.

## Regras `allow` e `deny`

Sintaxe:

```ini
allow PADRAO
# ou
deny PADRAO
```

- **Antes da primeira regra de encaminhamento:** regras globais, aplicadas a todas as conexões.
- **Depois de um redirecionamento:** regras referentes a esse redirecionamento, até a regra de encaminhamento seguinte.
- Se **não existir regra `allow`** aplicável, o acesso passa pela etapa de permissão implicitamente.
- Se existir pelo menos uma regra `allow` aplicável, a origem precisa corresponder a uma delas.
- Qualquer `deny` correspondente **bloqueia**, mesmo que um `allow` também corresponda. Não são regras estilo firewall sequencial “primeira correspondência vence”.
- Padrões aceitam `*` (zero ou mais caracteres) e `?` (um caractere). Não são CIDR e não aceitam hostname.

### Exemplo correto: rede local autorizada

```ini
192.168.25.35 18080 192.168.25.10 300
allow 192.168.25.*
```

**Não** acrescente `deny *`: isso bloquearia também a origem permitida.

### Exemplo correto: liberar uma rede, exceto um endereço

```ini
192.168.25.35 18080 192.168.25.10 300
allow 192.168.25.*
deny 192.168.25.99
```

### Dois erros frequentes

```ini
allow 0.0.0.0  # NÃO significa liberar todos os IPs
allow *        # libera todas as origens, se não houver deny correspondente
```

Use o firewall do sistema como proteção adicional; restringir o IP de escuta é mais seguro do que expor `0.0.0.0` sem necessidade.

## Logs e PID

| Diretiva | Efeito |
|---|---|
| `logfile /var/log/rinetd.log` | Registra conexões em arquivo. Sem esta diretiva, nenhum logfile é criado pelo rinetd. |
| `logcommon` | Solicita formato de log similar ao Common Log Format. |
| `pidlogfile /run/rinetd.pid` | Define caminho alternativo para o arquivo de PID, quando aplicável. |

O log padrão contém data/hora, IP de origem, IP/porta local, destino IP/porta, bytes recebidos/enviados e resultado. A escrita no logfile depende das permissões do usuário do serviço.

## Reload e testes

Em um serviço iniciado pelo systemd, verifique a configuração e as instruções da unidade antes de usar `systemctl reload`. O sinal `SIGHUP` solicita releitura de `/etc/rinetd.conf` (ou do arquivo passado com `-c`). **Nesta RC1 o reload com rollback e preservação total de sessões ainda não foi certificado.** Não teste mudanças arriscadas em produção.

Para confirmar conectividade TCP:

```bash
ss -lntup | grep 18080
ssh -p 18080 192.168.25.35
```

Para acompanhar logs do serviço:

```bash
journalctl -u rinetd-ng -n 50 --no-pager
```

## Referência e créditos

Baseado no manual `rinetd.8` do [projeto original](https://github.com/samhocevar/rinetd), de Thomas Boutell e Sam Hocevar. O código original permanece licenciado em GPL-2.0-or-later.
