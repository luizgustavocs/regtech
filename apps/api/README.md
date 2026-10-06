# regtech
Security-first RegTech/LegalOps SaaS for developers that correlates technical security findings (OWASP, headers, logs, TLS, auth) with regulatory impacts from LGPD and Marco Civil (Brazilian laws), delivering deterministic compliance diagnostics, risk scoring, and audit-ready insights.

RegTech/LegalOps SaaS

Plataforma SaaS de RegTech/LegalOps focada em autodiagnóstico e auditoria técnico-regulatória para aplicações web. O sistema correlaciona evidências técnicas de segurança — como headers HTTP, logs, TLS, autenticação, cookies e controles OWASP — com impactos legais relacionados à LGPD, Marco Civil da Internet e frameworks de compliance. A arquitetura foi projetada com foco em segurança, baixo consumo de recursos, auditabilidade, explicabilidade e escalabilidade, utilizando um núcleo determinístico de correlação entre findings técnicos e matrizes regulatórias.


================================================================================
RELATÓRIO DE AUDITORIA TÉCNICA E GOVERNANÇA: MOTOR DE CORRELAÇÃO REGULATÓRIA
================================================================================
Data de Fechamento: 19 de Maio de 2026
Status do Sistema: Funcional e Integrado
Arquitetura: Go (API v1) + Supabase (PostgreSQL com Connection Pooler)
Objetivo: Mapeamento automatizado de falhas técnicas contra frameworks legais
================================================================================

Este documento descreve detalhadamente cada etapa técnica, de infraestrutura e de 
tratamento de dados realizada na construção do microsserviço de auditoria e 
compliance regulatório (RegTech).

--------------------------------------------------------------------------------
ETAPA 1: DESIGN E MODELAGEM DE DADOS (POSTGRESQL / SUPABASE)
--------------------------------------------------------------------------------
A fundação do sistema foi estruturada no PostgreSQL hospedado no Supabase, adotando 
uma modelagem normalizada que separa as evidências coletadas em tempo de execução 
das obrigações legais e normativas estáticas.

1.1. Tabela de Achados (Findings)
   - Armazena as inconformidades técnicas disparadas pelos crawlers ou scanners.
   - Atributos principais:
     * id: UUIDv4 como chave primária.
     * rule_key: Identificador único da regra de conformidade (ex: 'MISSING_ACCESS_LOGS').
     * target: Escopo ou ambiente avaliado (ex: 'acc-secure-test').
     * evidence: Campo JSONB contendo o payload dinâmico da falha (ex: microsserviço 
       afetado, descrição do contêiner desmuntado e data/hora exata da detecção).
     * created_at: Timestamp com fuso horário da inserção do registro.

1.2. Tabela de Obrigações Legais (Obligations)
   - Catálogo estático contendo os enquadramentos legais e frameworks de segurança.
   - Atributos principais:
     * id: UUIDv4 como chave primária.
     * framework: String indexada identificando o corpo normativo (LGPD, MCI, OWASP).
     * section: Artigo, seção ou categoria específica (ex: 'Art. 46', 'Art. 15', 'A09:2021').
     * description: Descrição textual detalhada da exigência legal ou técnica em português.
     * criticality: Nível de severidade abstrata da norma (CRITICAL, HIGH, MEDIUM, LOW).

1.3. Mecanismo de Conectividade e Resiliência
   - Configuração do driver de conexão da API para apontar diretamente para o Bouncer 
     de gerenciamento de pool do Supabase (Transaction Mode), garantindo escalabilidade 
     sob alto volume de requisições concorrentes sem exaustão de sockets do banco.

--------------------------------------------------------------------------------
ETAPA 2: DESENVOLVIMENTO DA CAMADA DE NEGÓCIO E API (GOLANG)
--------------------------------------------------------------------------------
Construção do endpoint centralizador de relatórios na linguagem Go, focando em alta 
performance, tipagem estrita e processamento de regras em memória.

2.1. Rota de Auditoria
   - Exposição do endpoint: GET /api/v1/audit/report?target={nome_do_alvo}
   - Implementação de parsing rigoroso de parâmetros de URL para isolar o escopo do target.

2.2. Motor de Intersecção Legal e Cálculo de Impacto
   - O motor executa uma query composta que cruza o 'rule_key' do achado com as obrigações 
     legais correspondentes.
   - Para cada correlação encontrada, a API injeta dinamicamente dois campos contextuais:
     * impact_score: Um score numérico inteiro (0 a 100) que traduz o risco combinado 
       da falha técnica com a criticidade da lei violada.
     * explanation: Uma string gerada contextualmente detalhando exatamente o porquê 
       daquela falha técnica configurar uma violação direta daquele artigo ou seção específica.

2.3. Payload de Resposta (JSON)
   - O payload foi padronizado como um array de objetos complexos, onde cada item 
     contém o espelho completo do 'finding', o espelho da 'obligation' associada, 
     o 'impact_score' e a 'explanation'.

--------------------------------------------------------------------------------
ETAPA 3: VALIDAÇÃO PRÁTICA E MAPEAMENTO DE ENQUADRAMENTO REAL
--------------------------------------------------------------------------------
Para homologação do pipeline fim a fim, foi injetado um caso de teste real focado 
na falha 'MISSING_ACCESS_LOGS' (Ausência de logs de acesso no contêiner 'auth-service' 
em ambiente de produção). O motor respondeu correlacionando o achado a três pilares:

3.1. Pilar Proteção de Dados (LGPD)
   - Seção: Art. 46
   - Descrição: Dever de segurança, sigilo e adoção de medidas técnicas administrativas 
     aptas a proteger dados pessoais.
   - Impact Score: 90
   - Explicação: A ausência de logs impede a rastreabilidade de acessos a dados pessoais, 
     violando o dever de segurança técnica exigido pelo Art. 46 da LGPD.

3.2. Pilar Civil/Digital (Marco Civil da Internet - MCI)
   - Seção: Art. 15
   - Descrição: Obrigatoriedade da manutenção dos registros de acesso a aplicações de 
     internet sob sigilo e ambiente controlado.
   - Impact Score: 85
   - Explicação: O Marco Civil da Internet exige estritamente a guarda de registros de 
     aplicação. Não registrar logs descumpre diretamente a obrigação legal do Art. 15.

3.3. Pilar Técnico-Cibernético (OWASP)
   - Seção: A09:2021
   - Descrição: Security Logging and Monitoring Failures - Falhas em logs que impedem 
     a detecção ativa de ataques.
   - Impact Score: 75
   - Explicação: A falta de logs centralizados e auditáveis enquadra-se diretamente na 
     categoria A09:2021 do OWASP Top Ten, facilitando ações maliciosas persistentes.

--------------------------------------------------------------------------------
ETAPA 4: SOLUÇÃO DE ANOMALIAS DE TRANSPORTE E ENCODING (WINDOWS / POWERSHELL)
--------------------------------------------------------------------------------
Durante os testes de integração locais a partir do ambiente Windows, foi detectado um 
comportamento de corrupção de caracteres (Mojibake) nas strings acentuadas (ex: 'seguranÃ§a').

4.1. Diagnóstico da Causa Raiz
   - A API em Go e o banco Supabase trafegavam os dados corretamente em UTF-8. No entanto, 
     o cmdlet `Invoke-RestMethod` do Windows PowerShell e o alias padrão do `curl` (que aponta 
     para `Invoke-WebRequest`) interceptavam o fluxo binário e o decodificavam utilizando a 
     tabela de páginas local do Windows (Windows-1252 / ISO-8859-1), quebrando acentos e cedilhas.

4.2. Mitigação e Correção Aplicadas
   - Foram implementadas e validadas duas abordagens de contorno no terminal para garantir a 
     exibição limpa e auditável dos dados em UTF-8:
     
     Abordagem A (Bypass pelo Executável Nativo):
     Utilização explícita do binário do cURL compilado para Windows, ignorando o alias do PowerShell:
     > curl.exe -s "http://localhost:8080/api/v1/audit/report?target=acc-secure-test"

     Abordagem B (Decodificação Forçada via .NET):
     Captura do objeto de resposta do PowerShell e remontagem manual dos bytes utilizando o 
     módulo de encoding UTF-8 do .NET Core:
     > $response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/audit/report?target=acc-secure-test" -Method Get
     > [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::GetEncoding("iso-8859-1").GetBytes(($response | ConvertTo-Json -Depth 5)))

--------------------------------------------------------------------------------
CONCLUSÃO DO STATUS ATUAL
--------------------------------------------------------------------------------
O motor encontra-se estável, com persistência íntegra, cálculo de impacto preciso 
e saída de dados devidamente sanitizada e legível. O pipeline está pronto para 
o recebimento de novas chaves de regras e expansão do dicionário regulatório.
================================================================================