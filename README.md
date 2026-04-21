# mini-soc-wazuh-sysmon

Projeto de laboratório focado em Blue Team para coleta, análise e detecção de eventos em endpoint Windows, com Wazuh como SIEM e Sysmon como fonte de telemetria avançada. O ambiente foi construído em máquinas virtuais, com autenticação de agente, ingestão de logs e criação de regra customizada para detecção de PowerShell.

## Objetivo
Implementar um ambiente de monitoramento capaz de detectar eventos de segurança em um endpoint Windows.

## Arquitetura

- Ubuntu (Wazuh Server)
- Windows 11 (Endpoint monitorado)
- Sysmon (telemetria avançada)

## Fluxo

1. Instalação do Wazuh
2. Conexão do agente
3. Integração com Sysmon
4. Coleta de logs
5. Criação de regra de detecção

## Evidências

### Agente conectado
![Agent](images/agent-online.png)

### Eventos coletados
![Logs](images/sysmon-events.png)

### Alerta gerado
![Alert](images/alert-powershell.png)

## Regra criada

```xml
<group name="windows,sysmon,custom,">
  <rule id="100001" level="10">
    <if_field name="data.win.eventdata.Image">powershell.exe</if_field>
    <description>Execução de PowerShell detectada</description>
  </rule>
</group>
