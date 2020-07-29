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
from burp import IScannerCheck
from burp import IExtensionStateListener
from burp import IBurpExtenderCallbacks
from burp import IMessageEditor
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IHttpRequestResponse
from burp import IExtensionHelpers
from burp import IHttpRequestResponseWithMarkers
from burp import ITab
from burp import IMessageEditorController
from burp import ITextEditor
from burp import IHttpService
from burp import IScanIssue
from burp import IScannerListener

from array import array

from javax import swing

from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import Dimension
from java.awt import Toolkit
from java.awt import Color
from java.awt import Font

from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent

from java.awt.datatransfer import StringSelection

from javax.swing import (JMenuItem)
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JOptionPane

from javax.swing.border import EmptyBorder

from java.io import File

from java.util import List
from java.util import ArrayList

import os
import re
import sys
import csv
import json
import time
import uuid
import requests
import threading
import traceback
import java.util.List

from urlparse import urlparse

# handles ASCII encoding errors.
# reload(sys)
# sys.setdefaultencoding('utf-8')


class BurpExtender(IBurpExtender, IScannerListener, IContextMenuFactory,
                   ActionListener, IMessageEditorController, ITab, ITextEditor,
                   IHttpService, IScanIssue, IHttpRequestResponseWithMarkers,
                   IBurpExtenderCallbacks):

    def __init__(self):
        self.msgrel = False
        print("[+] Carregando Integração GAT Digital ...")

    def registerExtenderCallbacks(self, callbacks):

        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()

        # set our extension name
        self._callbacks.setExtensionName("GAT Digital Integração")
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerScannerListener(self)

        self.gui_elements = self.build_gui()
        callbacks.customizeUiComponent(self.gui_elements)
        callbacks.addSuiteTab(self)
        self.reload_config()

        print("[+] GAT Digital Extension carregado!")

    def actionPerformed(self, event):
        requestResponses = self.invocation.getSelectedMessages()
        chosts, ihosts = self.countHostIssues(requestResponses)
        dialogConfirm = JOptionPane.showOptionDialog(
            None,
            "{} host(s) com {} Issues,\n Continuar?".format(
                chosts, ihosts
            ),
            "Confirma processamento?",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE, None, ["Não", "Sim"], "Não")

        if not dialogConfirm:
            JOptionPane.showMessageDialog(
                None,
                "Cancelado processamento/envio de Issues para GAT",
                "Informativo",
                JOptionPane.INFORMATION_MESSAGE)
            return

        for reqResp in requestResponses:
            url = reqResp.getHttpService()
            requestIssues = self._callbacks.getScanIssues(str(url))
            self.issues_results = requestIssues
            self.fileId = []
            listIssues = []

            if requestIssues:

                if len(requestIssues) > 0:

                    for i in requestIssues:
                        scanissue = i
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
                        IssueDescBk = scanissue.getIssueBackground()
                        IssueDesc = scanissue.getIssueDetail()
                        IssueRecomBk = scanissue.getRemediationBackground()
                        IssueRecom = scanissue.getRemediationDetail()

                        if IssueType:
                            issue['IssueType'] = scanissue.getIssueType()
                        else:
                            issue['IssueType'] = 0000

                        if IssueName:
                            issue['DetailsFinding_Title'] = IssueName
                            issue['Recomenation_Title'] = IssueName
                        else:
                            issue['DetailsFinding_Title'] = " "
                            issue['Recomenation_Title'] = " "

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
                            issue['Severity'] = " "

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

                        issue['Description'] = "{}{}{}".format(
                            IssueDescBk, sep, IssueDesc)

                        issue['Recommendation'] = "{}{}{}".format(
                            IssueRecomBk, sep, IssueRecom)

                        listIssues.append(issue)

                    self.generateReportGat(listIssues)

            # self.sendIssues()
            self.launchThread(self.sendIssues)

        print("[+] Finalizado processamento do(s) host(s)")

    def createMenuItems(self, invocation):
        self.invocation = invocation
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            sendToGAT = JMenuItem("Enviar Issues para GAT")

            # sendToGAT.setForeground(Color.WHITE)
            FONT = sendToGAT.getFont()
            sendToGAT.setFont(Font(
                FONT.getFontName(), Font.BOLD, FONT.getSize())
            )
            sendToGAT.addActionListener(self.actionPerformed)

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

        save_btn = JButton('Salvar/Conectar', actionPerformed=self.save_config)

        self.host_api = JTextField(100)
        self.api_token = JTextField(100)

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

        btns.add(save_btn)

        return panel

    def save_config(self, _):
        """Save settings."""
        save_setting = self._callbacks.saveExtensionSetting
        save_setting('host_api', self.host_api.getText())
        save_setting('api_token', self.api_token.getText())
        self.msgrel = True
        self.reload_config()

    def reload_config(self):
        """Reload settings."""
        if self.msgrel:
            print("[+] GAT Digital Extension Recarregando ...")
        load_setting = self._callbacks.loadExtensionSetting
        host_api_url = load_setting('host_api') or ''
        host_api_token = load_setting('api_token') or ''

        self.host_api.setText(host_api_url)
        self.api_token.setText(host_api_token)

        try:
            self.apiGAT = GAT(host_api_url, host_api_token)
            vapi = self.apiGAT.CheckAuth()

            if vapi.status_code == 200:
                data = json.loads(vapi.text)
                print("[ ] {}, {} conectado".format(
                    data['name'], data['email'])
                )
                if self.msgrel:
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

    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "GAT Settings"

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.gui_elements

    def generateReportGat(self, rows):

        Id = uuid.uuid4().hex
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
                csv_file, fieldnames=fields, lineterminator='\n'
            )
            writer.writeheader()
            # for row in rows:
            writer.writerows(rows)
        csv_file.close()

        self.fileId.append(Id)

    def generateReportXML(self, format):
        if format != 'XML':
            format = 'HTML'

        path = os.getcwd()

        file_name = '{}\exports\gat_report_t.xml'.format(path)
        self._callbacks.generateScanReport(
            format, self.issues_results, File(file_name)
        )

        time.sleep(5)

        return

    def sendIssues(self):
        for Id in self.fileId:
            print("[+] Processando ID: {}".format(Id))

            path = os.getcwd()
            folder = "\\exports\\"
            file_name = "{}{}{}.csv".format(path, folder, Id)

            self.apiGAT.SendCSV(file_name)

    def launchThread(self, targetFunction, arguments=None):
        """Launches a thread against a specified target function"""
        if arguments:
            t = threading.Thread(target=targetFunction, args=arguments)
        else:
            t = threading.Thread(target=targetFunction)
        t.daemon = True
        t.start()

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


class GAT():
    def __init__(self, api, token):
        self.authorization = token
        self.gahost = api

    def RequestAPI(
            self, api,
            method, resource, token, payload=None, file=None, header=None):
        """
        Função generica para acesso API GAT
        """
        protocol = "http" if api == "localhost" else "https"
        gatPoint = "{}://{}{}".format(protocol, api, resource)
        try:
            with requests.Session() as s:
                s.headers = {
                    'Content-Type': "application/json",
                    'cache-control': "no-cache",
                    'Authorization': 'Bearer %s' % token
                }
                r = s.request(
                    method, gatPoint, json=payload, headers=header, files=file)
        except Exception:
            response = {}
            response["status_code"] = 500
            r = DotDict(response)
            return r

        return r

    def CheckAuth(self):
        """
        Validar api + token GAT
        """
        resource = "/api/v1/me"
        response = self.RequestAPI(self.gahost, 'GET', resource,
                                   self.authorization)

        return response

    def SendCSV(self, filename):
        """
        Enviar CSV para o GAT efetuar o parser das Issues
        """
        with open(filename, 'rb') as csv:
            name_csv = os.path.basename(filename)
            file = {'file': (name_csv, csv, "text/csv", {'Expires': "0"})}
            resource = "/app/vulnerability/upload/api/Burp"
            response = self.RequestAPI(self.gahost, 'POST', resource,
                                       self.authorization, file=file)

        csv.close()

        if response.status_code == 200:
            print("[+] Success - {}".format(response.text))
            os.remove(filename)
        else:
            print("[-] Falhou o envio das Issues ID: {} - code:{}".format(
                name_csv.replace(".csv", ""), response.status_code))
            # show message alert error SEND CSV to GAT
            # JOptionPane.showMessageDialog(
            #     None,
            #     "Falhou o envio das Issues",
            #     "Error",
            #     JOptionPane.ERROR_MESSAGE)
            os.remove(filename)

        return response


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
