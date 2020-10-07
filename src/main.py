# -*- coding: utf-8 -*-

"""
/*******************************************************************************
  Copyright (C) 2020, GAT Digital - Almeida, Julio.

  Filename: main.py
  File Id: 0001
  Project: Burp Extension Gat Integration
  Description: Extension to integration scan results to centralized gat scans


  Date           Version      Action          Author             Changes
  ------------------------------------------------------------------------------
  2020/07/17      1.0          Init            Julio C. Almeida   N/A
*******************************************************************************/
"""

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IScannerListener
from burp import ITab
from burp import IScanIssue
from burp import IHttpService

from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import Color
from java.awt import Font

from java.awt.event import ActionListener


from javax.swing import (JMenuItem)
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JOptionPane

from javax.swing.border import EmptyBorder

from java.io import File
from java.net import URL
from java.net import URI

from java.util import ArrayList

import os
import re
import sys
import csv
import json
import time
import uuid
import traceback

from threading import Thread


# handles ASCII encoding errors.
reload(sys)
sys.setdefaultencoding('utf-8')


class BurpExtender(IBurpExtender, IScannerListener, IContextMenuFactory,
                   ActionListener, ITab, IHttpService, IScanIssue,
                   IBurpExtenderCallbacks):

    def __init__(self):
        self.msgrel = False
        self.project = False
        print("[+] Carregando GAT Digital Extension ...")

    def registerExtenderCallbacks(self, callbacks):
        """
        registrar classes
        """
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName("GAT Digital Integration")

        self.gui_elements = self.build_gui()
        callbacks.customizeUiComponent(self.gui_elements)
        callbacks.addSuiteTab(self)

        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerScannerListener(self)

        save_setting = self._callbacks.saveExtensionSetting
        save_setting('project_id', None)

        self.reload_config()
        print("[+] GAT Digital Extension carregado!")

    def newScanIssue(self, issue):
        print("[+] Issue encontrada (%s)" % issue.getIssueName())
        return

    def actionTarget(self, event):
        print("*" * 80)

        self.fileId = []
        requestResponses = self.invocation.getSelectedMessages()
        chosts, ihosts = self.countHostIssues(requestResponses)
        # dialogConfirm = JOptionPane.showOptionDialog(
        #     None,
        #     "Encontrado {} host(s) com {} Issues,\n Continuar?".format(
        #         chosts, ihosts
        #     ),
        #     "Confirmar",
        #     JOptionPane.DEFAULT_OPTION,
        #     JOptionPane.QUESTION_MESSAGE, None, ["Cancelar", "Sim"], "Sim"
        # )

        # if not dialogConfirm:
        #     JOptionPane.showMessageDialog(
        #         None,
        #         "Cancelado processamento/envio de Issues para GAT",
        #         "Informativo",
        #         JOptionPane.INFORMATION_MESSAGE)

        load_setting = self._callbacks.loadExtensionSetting
        project_id = load_setting('project_id') or None

        if not project_id:
            projectq = JOptionPane.showInputDialog(
                None,
                "Qual projeto enviar Issues?",
                "ID Projeto"
            )

            if projectq is not None:
                ever = JOptionPane.showOptionDialog(
                    None,
                    "Solicitar Id Projeto novamente?",
                    "da sessão atual?",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.QUESTION_MESSAGE, None, [
                        "Nunca", "Sim"], "Sim"
                )

                # let user select parameters for new session
                if ever == JOptionPane.OK_OPTION:
                    save_setting = self._callbacks.saveExtensionSetting
                    save_setting('project_id', projectq)
                # else:
                #     return

        for reqResp in requestResponses:
            url = reqResp.getHttpService()
            requestIssues = self._callbacks.getScanIssues(str(url))
            listIssues = []

            if requestIssues:
                if len(requestIssues) > 0:
                    for i in requestIssues:
                        scanissue = i
                        if scanissue.getIssueName() not in ['']:
                            sep = "<br><hr><br>"
                            issue = {}
                            issue['Tool_Type'] = "BURP"
                            IssueType = scanissue.getIssueType()
                            IssueName = scanissue.getIssueName()
                            IssueCrit = scanissue.getSeverity()
                            IssueConf = scanissue.getConfidence()
                            protocol = scanissue.getHttpService().getProtocol()
                            host = scanissue.getHttpService().getHost()
                            IssuePath = i.getUrl().getPath()
                            IssueDesc = scanissue.getIssueDetail()
                            IssueDescBk = scanissue.getIssueBackground()
                            IssueRecom = scanissue.getRemediationDetail()
                            IssueRecomBk = scanissue.getRemediationBackground()

                            if IssueType:
                                issue['IssueType'] = scanissue.getIssueType()
                            else:
                                issue['IssueType'] = 0000

                            if IssueName:
                                issue['DetailsFinding_Title'] = IssueName
                                issue['Recomenation_Title'] = IssueName
                            else:
                                issue['DetailsFinding_Title'] = "No Issue name"
                                issue['Recomenation_Title'] = "No Issue name"

                            if "False positive" in IssueCrit:
                                sTag = "False positive"
                                IssueCrit = ""
                            elif "Information" in IssueCrit:
                                IssueCrit = "Informative"
                                sTag = ""
                            else:
                                sTag = ""

                            if IssueCrit:
                                issue['Severity'] = IssueCrit
                            else:
                                issue['Severity'] = "Informative"

                            issue['Web_Application_URI'] = "{}://{}".format(
                                protocol, host)

                            if IssuePath:
                                issue['Web_Application_Path'] = IssuePath
                            else:
                                issue['Web_Application_Path'] = "/"

                            if IssueConf:
                                issue['fTag'] = IssueConf
                            else:
                                issue['fTag'] = " "

                            issue['sTag'] = sTag

                            if IssueDescBk is not None:
                                issue['Description'] = IssueDescBk.replace(
                                    "\n", ""
                                )
                            else:
                                issue['Description'] = ""

                            if IssueDesc is not None:
                                issue['Description'] += "{}{}".format(
                                    sep,
                                    IssueDesc.replace(
                                        "\n", ""
                                    )
                                )

                            if IssueRecomBk is not None:
                                issue[
                                    'Recommendation'
                                ] = IssueRecomBk.replace(
                                    "\n", ""
                                )
                            else:
                                issue['Recommendation'] = IssueName

                            if IssueRecom is not None:
                                issue['Recommendation'] += "{}{}".format(
                                    sep,
                                    IssueRecom.replace(
                                        "\n", ""
                                    )
                                )

                            listIssues.append(issue)

                    self.generateReportGat(listIssues)

        # iniciar threads
        print("[+] Thread(s) Iniciada(s)...")
        print("[+] Enviando {} host(s), total de {} Issue(s),\n".format(
            chosts, ihosts
        ))
        self.launchThread(self.sendIssues)

    def actionScanner(self):
        pass

    def createMenuItems(self, invocation):
        self.invocation = invocation
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            sendToGAT = JMenuItem("Enviar Issues para GAT")

            # sendToGAT.setForeground(Color.ORANGE)
            FONT = sendToGAT.getFont()
            sendToGAT.setFont(Font(
                FONT.getFontName(), Font.BOLD, FONT.getSize())
            )

            sendToGAT.addActionListener(self.actionTarget)

            menuItems = ArrayList()
            menuItems.add(sendToGAT)
            return menuItems

        else:
            # TODO: add support for other tools
            pass

    def build_gui(self):
        """Construct GUI elements."""
        panel = JPanel()
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        save_btn = JButton('Salvar', actionPerformed=self.save_config)

        self.host_api = JTextField(100)
        self.api_token = JTextField(100)
        self.project_id = JTextField(100)

        labels = JPanel(GridLayout(0, 1))
        labels.setBorder(EmptyBorder(10, 10, 10, 10))
        inputs = JPanel(GridLayout(0, 1))
        inputs.setBorder(EmptyBorder(10, 10, 10, 10))
        btns = JPanel(GridLayout(0, 1))
        btns.setBorder(EmptyBorder(10, 10, 10, 10))
        panel.add(labels, BorderLayout.WEST)
        panel.add(inputs, BorderLayout.CENTER)
        panel.add(btns, BorderLayout.SOUTH)

        labels.add(JLabel('API Url:'))
        inputs.add(self.host_api)
        labels.add(JLabel('API Token:'))
        inputs.add(self.api_token)
        labels.add(JLabel('Project ID:'))
        inputs.add(self.project_id)

        btns.add(save_btn)

        return panel

    def save_config(self, _):
        """Save settings."""
        url = self.host_api.getText()
        token = self.api_token.getText()

        if re.match('https?://', url):
            url = re.sub('https?://', '', url)

        if url[-1:] == "/":
            url = url[:-1]

        if re.match('^(?i)Bearer ', token):
            token = re.sub('^(?i)Bearer ', '', token)

        if not re.match(
            '([a-f\d]{8})-([a-f\d]{4})-([a-f\d]{4})-([a-f\d]{4})-([a-f\d]{12})',
                token
        ):
            JOptionPane.showMessageDialog(
                None,
                "Formato de TOKEN invalido!",
                "Error",
                JOptionPane.ERROR_MESSAGE)
            return

        save_setting = self._callbacks.saveExtensionSetting
        save_setting('host_api', url)
        save_setting('api_token', token)
        self.msgrel = True
        self.reload_config()
        return

    def reload_config(self):
        """Reload settings."""
        load_setting = self._callbacks.loadExtensionSetting
        host_api_url = load_setting('host_api') or ''
        host_api_token = load_setting('api_token') or ''
        project_id = ''

        self.host_api.setText(host_api_url)
        self.api_token.setText(host_api_token)
        self.project_id.setText(project_id)

        if self.msgrel:
            if self.host_api and self.api_token:
                JOptionPane.showMessageDialog(
                    None,
                    "API token, API url dados salvo\n ",
                    "Informativo",
                    JOptionPane.INFORMATION_MESSAGE)

                print("[+] API token, API url dados salvo")
                print("[+] Recarregue: GAT Digital Extension")
                return

        try:
            vapi = self.checkAuth()

            if vapi.status_code == 200:
                data = json.loads(vapi.text)
                print("[ ] Conectado: {}, {}".format(
                    data['name'], data['email'])
                )
                # if self.msgrel:
                JOptionPane.showMessageDialog(
                    None,
                    "Conectado: {}, {}".format(
                        data['name'], data['email']),
                    "Informativo",
                    JOptionPane.INFORMATION_MESSAGE)

            else:
                raise Exception("Status_Code({})".format(vapi.status_code))

        except Exception as e:
            print("[-] GAT Settings, erro ao conectar na API.")
            print("[-] Exception: {}".format(e))

        return

    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "GAT Settings"

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.gui_elements

    def generateReportGat(self, rows):
        quote = '"'
        Id = uuid.uuid4().hex
        self.fileId.append(Id)
        path = os.getcwd()
        folder = "\\exports\\"
        file_name = "{}{}{}.csv".format(path, folder, Id)

        with open(file_name, mode='w') as csv_file:
            fields = [
                'Tool_Type', 'IssueType', 'DetailsFinding_Title', 'Severity',
                'Web_Application_URI', 'Web_Application_Path', 'fTag', 'sTag',
                'Description', 'Recomenation_Title', 'Recommendation'
            ]
            writer = csv.DictWriter(
                csv_file,
                fieldnames=fields,
                quotechar=quote,
                quoting=csv.QUOTE_NONNUMERIC,
                lineterminator='\n'
            )
            writer.writeheader()
            writer.writerows(rows)
        csv_file.close()

        return Id

    def sendIssues(self):
        for Id in self.fileId:
            print("[+] Processando ID: {}".format(Id))
            path = os.getcwd()
            folder = "\\exports\\"
            file_name = "{}{}{}.csv".format(path, folder, Id)
            self.launchThread(self.requestAPI, arguments=file_name)

    def launchThread(self, targetFunction, arguments=None, retur=False):
        """Launches a thread against a specified target function"""
        if arguments:

            t = Thread(
                name='args', target=targetFunction, args=(arguments, )
            )
        else:
            t = Thread(
                name='no-args', target=targetFunction
            )

        t.setDaemon(True)
        t.start()

        if retur:
            r = t.join()
            return r

    def countHostIssues(self, requestResponses):
        count = 0
        icount = 0
        for reqResp in requestResponses:
            url = reqResp.getHttpService()
            requestIssues = self._callbacks.getScanIssues(str(url))
            if requestIssues:
                if len(requestIssues) > 0:
                    count += 1
                    for issue in requestIssues:
                        icount += 1

        return count, icount

    def requestAPI(self, filename):
        load_setting = self._callbacks.loadExtensionSetting
        api_uri = load_setting('host_api') or ''
        api_token = load_setting('api_token') or ''
        project_id = load_setting('project_id') or ''

        name_csv = os.path.basename(filename)
        # print(project_id)
        if project_id:
            # if re.match(
            #     '([a-f\d]{8})-([a-f\d]{4})-([a-f\d]{4})-([a-f\d]{4})-([a-f\d]{12})',
            #     project_id
            # ):
            resource = "/app/vulnerability/upload/api/Burp/{}".format(
                project_id
            )
        else:
            resource = "/app/vulnerability/upload/api/Burp"

        # print(resource)
        protocol = "http" if api_uri == "localhost" else "https"
        gatPoint = "{}://{}{}".format(protocol, api_uri, resource)

        try:
            dataList = []
            api_url = URL(gatPoint)
            boundary = name_csv.replace(".csv", "")

            headers = ArrayList()
            headers.add('POST %s HTTP/1.1' % resource)
            headers.add('Host: %s' % api_uri)
            headers.add('Authorization: Bearer %s' % api_token)
            headers.add('Accept: application/json')
            headers.add(
                'Content-type: multipart/form-data; boundary={}'.format(
                    boundary)
            )

            dataList.append('--' + boundary)
            dataList.append(
                'Content-Disposition: form-data; name=file; filename={}'.format(
                    name_csv)
            )

            dataList.append('Content-Type: text/csv')
            dataList.append('')
            with open(filename) as f:
                dataList.append(f.read())

            dataList.append('--'+boundary+'--')
            dataList.append('')
            body = '\r\n'.join(dataList)

            newBody = self._helpers.bytesToString(body)

            newRequest = self._helpers.buildHttpMessage(headers, newBody)

            requestInfo = self._helpers.analyzeRequest(newRequest)
            headers = requestInfo.getHeaders()

            response = self._callbacks.makeHttpRequest(
                api_url.getHost(), 443, True, newRequest)

            response_info = self._helpers.analyzeResponse(response)

            response_value = self._helpers.bytesToString(
                response)[response_info.getBodyOffset():].encode("utf-8")

        except Exception as e:
            print("[-] Falha arquivo/envio de Issues ID:{} - Error: {}".format(
                name_csv, e)
            )

        if response_info.getStatusCode() == 200:
            self.removeCSV(filename)
            print("[+] Success ID: {}".format(name_csv.replace(".csv", "")))

        else:
            print("[-] Falhou o envio do ID: {} - code :{}".format(
                name_csv.replace(".csv", ""), response_info.getStatusCode()))

            if response_value:
                print("Error: {}".format(response_value))

            JOptionPane.showMessageDialog(
                None,
                "Falhou o envio das Issues",
                "Error",
                JOptionPane.ERROR_MESSAGE)
            self.removeCSV(filename)

    def checkAuth(self):
        """
        Validar api + token GAT
        """
        load_setting = self._callbacks.loadExtensionSetting
        api_uri = load_setting('host_api') or ''
        api_token = load_setting('api_token') or ''

        resource = "/api/v1/me"

        protocol = "http" if api_uri == "localhost" else "https"
        gatPoint = "{}://{}{}".format(protocol, api_uri, resource)

        api_url = URL(gatPoint)

        headers = ArrayList()
        headers.add('GET %s HTTP/1.1' % resource)
        headers.add('Host: %s' % api_uri)
        headers.add('Authorization: Bearer %s' % api_token)
        headers.add('Content-Type: application/json')

        newRequest = self._helpers.buildHttpMessage(headers, None)

        requestInfo = self._helpers.analyzeRequest(newRequest)
        headers = requestInfo.getHeaders()

        response = self._callbacks.makeHttpRequest(
            api_url.getHost(), 443, True, newRequest)

        response_info = self._helpers.analyzeResponse(response)
        response_value = self._helpers.bytesToString(
            response)[response_info.getBodyOffset():].encode("utf-8")

        response = {}
        response['status_code'] = response_info.getStatusCode()
        response['text'] = response_value
        r = DotDict(response)
        return r

    def removeCSV(self, path):
        """ param <path> could either be relative or absolute. """
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
        else:
            raise ValueError("file {} is not a file".format(path))


class DotDict(dict):
    """dot.notation access to dictionary attributes"""

    def __getattr__(self, attr):
        return self.get(attr)
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __getstate__(self):
        return self

    def __setstate__(self, state):
        self.update(state)
        self.__dict__ = self
