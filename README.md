**Burp Extension, integration GAT Digital**

Extensão para o Burp desenvolvida em ambiente Python.

*Integração via interface do Burp para efetuar o envio de todos os apontamentos com base na seleção de Target --> Hosts únicos ou múltiplos*

---

## Instalação

* Requisitos:
    1. ***BURP PROFESSIONAL***
    2. ***Jython JAR***

### Primeiro passo - **Clonar** repositório para o Desktop/Server onde está o Burp Professional instalado.

```
git clone https://bitbucket.org/IBLISS-GAT-DEV/gat-burp-extension.git
```

### Clicar no Tab **Extender**
1. Ir no Tab **Options** configurar em "Python Evironment"
    * Location of Jython standalone JAR file, configurar para a pasta/arquivo: "~\burp-extension\jython\jython-standalone-2.7.2.jar"


![Alt text](images/img-1.png?raw=true "Environment Configuração")

2. Ir no Tab **Extender**
    * Clicando em "Add", seguir o wizard em "Extension Details"
    selecionar "Type" Python e selecionar o arquivo main.py em: "~\burp-extension\src\main.py"

![Alt text](images/img-2.png?raw=true "Extension Configuração")

### Clicar no Tab **GAT Settings**
* Configurar API Url e API Token, clicar em Salvar. Efetuar o reload da extension GAT Digital Integration no Tab **Extender**

![Alt text](images/img-4.png?raw=true "API Configuração")

* Com os dados de Url e Token, será exibido um alerta confirmando a autenticação

![Alt text](images/img-5.png?raw=true "API Conectado")
---

## Utilizando a extensão
No Tab "Target" ao clicar com botão direito do mouse, terá disponível a opção no menu suspenso "Enviar Issues para GAT"

![Alt text](images/img-6.png?raw=true "Menu Enviar")

Pode ser utilizado selecionando um único hosts ou multiplos hosts, a cada envio será confirmado o número de hosts e quantidade de Issues será enviada.

![Alt text](images/img-7.png?raw=true "Menu Enviar")

![Alt text](images/img-3.png?raw=true "Enviando Issues para GAT")

Após o envio no Tab "Extender", subTab "Output" será confirmado o processamento e envio das Issues.

![Alt text](images/img-8.png?raw=true "Enviando Issues para GAT")

## Conferindo no GAT
Ao acessar "GAT" já estará disponível as notificações de todos os processos enviados via Extensão do BURP

![Alt text](images/img-9.png?raw=true "Lista Uploads")

Acessando o menu laterial "Integração" é possivel verificar maiores informações sobre o processamento dos arquivos com os Apontamentos enviados para o "GAT".

![Alt text](images/img-10.png?raw=true "Maiores Infos Processo")
---
