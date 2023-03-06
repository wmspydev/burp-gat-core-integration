**Burp Extension, integration GAT Digital**

*Submitting Issues analyzed in Burp based on Target selection -> Single or multiple Hosts to GAT CORE*

---

## Installation

* Requirements:
    1. ***BURP PROFESSIONAL***
    2. ***Jython JAR***

### First step - **Clone** the repository for the location where Burp Professional is installed..

### Click on Tab **Extensions** click on settings, new windows open.
1. Go to subTab **Extensions** set to "Python Evironment"
     * Location of Jython standalone JAR file, set to the folder / file: "~ \ burp-extension \ jython \ jython-standalone-2.7.2.jar"

![Alt text](images/img-1.png?raw=true "Environment Configuration")

2. Go to subTab **Extensions**
     * Clicking on "Add", following the wizard on "Extension Details"
     select "Type" Python and select the main.py file at: "~\burp-gat-core-integration\src\main.py"

![Alt text](images/img-2.png?raw=true "Extension Configuration")

### Click on Tab **GAT Core Settings**
* Configure your API Url and API Token, click Save. Reload the GAT Core Integration extension in Tab ** Extender **
* If u are using PROJECT ID it´s print hash in textbox

![Alt text](images/img-4.png?raw=true "API Configuration")

* When you finish entering the Url, Token and Reload, popup will be displayed confirming successful authentication

![Alt text](images/img-5.png?raw=true "API Connect")
---
## New Menu for GAT Infosec on TARGET in Extensions subMenu
![Alt text](images/img-6.png?raw=true "Sending")
## Using the extension
In the "Target" Tab when clicking with the right mouse button, the option submenu "Extensions" click on "GAT CORE Integration" --> "Sending Issues" will be available in the drop-down menu

![Alt text](images/img-3.png?raw=true "Sending Issues")

After clicking on "Sending Issues", you must confirm project to send hosts or not use project.

![Alt text](images/img-7.png?raw=true "Sending")

The number of hosts will be confirmed and their number of issues. After sending in the Tab "Extender", subTab "Output" will be confirmed the processing and sending of Issues.

![Alt text](images/img-8.png?raw=true " Issues GAT Core Send")

## Checking-in GAT CORE
When accessing "GAT Core", notifications of all processes sent via BURP Extension will be available

![Alt text](images/img-9.png?raw=true "Listing Uploads")

Accessing the side menu "Integration" it is possible to check more information about the processing of the files with the Notes sent to the "GAT Core"

![Alt text](images/img-10.png?raw=true "More infos process")
---
