**Burp Extension, integration GAT Digital**

Extensão para o Burp desenvolvida em ambiente Python.

*Integração via interface do Burp para efetuar o envio de todos os apontamentos com base na seleção de Target --> Hosts únicos ou múltiplos*

---

## Instalação

* Requisitos:
    1. ***BURP PROFESSIONAL***
    2. ***Jython JAR***
    3. ***Aditional Modules Python***

### Clicar no Tab **Extender**
1. Ir no Tab **Options** configurar em "Python Evironment"
    * Location of Jython standalone JAR file, configurar para a pasta/arquivo: "~\burp-extension\jython\jython-standalone-2.7.2.jar"

    * Folder for loading modules(optional), configurar para a pasta: "~\burp-extension\src\modules"

![Alt text](images/img-1.png?raw=true "Environment Configuração")

2. Ir no Tab **Extensions**
    * Clicando em "Add", seguir o wizard em "Extension Details"
    selecionar "Type" Python e selecionar o arquivo main.py em: "~\burp-extension\src\main.py"

![Alt text](images/img-2.png?raw=true "Extension Configuração")

### Clicar no Tab **GAT Settings**
* Configurar API Url e API Token, clicar em Salvar/Conectar.

![Alt text](images/img-4.png?raw=true "API Configuração")
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

---
