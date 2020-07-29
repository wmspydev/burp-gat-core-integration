



    def getSelectedScanIssues(self):

        self.issues_results = self._callbacks.getScanIssues(self.url)
        issues = self.ctxMenuInvocation.getSelectedIssues()
        listIssues = []

        # parses currently selected finding to a string
        if issues:
            if len(issues) >= 1:
                """ one or more issues can be sent
                    (cmd select for example within target...) """

                for self.m in issues:
                    scanissue = self.m

                    # for scanissue in self.m.getIssues():
                    issue = {}
                    issue['url'] = scanissue.getUrl().toString()
                    issue['severity'] = scanissue.getSeverity()
                    issue['issuetype'] = scanissue.getIssueType()
                    issue['issuename'] = scanissue.getIssueName()
                    # issue['issuedetail'] = scanissue.getIssueDetail()
                    # issue['confidence'] = scanissue.getConfidence()
                    issue['host'] = scanissue.getHttpService().getHost()
                    issue['port'] = scanissue.getHttpService().getPort()
                    issue['protocol'] = scanissue.getHttpService().getProtocol()
                    # messages = []
                    # for httpmessage in scanissue.getHttpMessages():
                    #     crequest = httpmessage.getRequest()
                    #     cresponse = httpmessage.getResponse()
                    #     if crequest:
                    #         request = httpmessage.getRequest().tostring()
                    #         request = request.encode('utf-8')
                    #     if cresponse:
                    #         response = httpmessage.getResponse().tostring()
                    #         response = response.encode('utf-8')

                    #     messages.append((request,
                    #                      response))
                    # issue['messages'] = messages
                    listIssues.append(issue)

                self.generateReportGat(listIssues)
                # # print self.m
                # # burp.sfg@3b784b06 # type <type 'burp.sfg'>

                # # add requestResponseWithMarkers to be global so can be included in scanIssue
                # requestResponse = self.m.getHttpMessages()

                # print "RequestResponse: ", requestResponse

                # # returns
                # l = array.tolist(requestResponse)
                # # print l
                # # print l[0]

                # # if there is more than one request response to a finding...
                # if len(l) > 1:
                #     k = len(l)
                #     q = 1
                #     for r in l:

                #         # call functionality to handle issues
                #         self.processRequest(r, q, k)
                #         q = q + 1

                # elif len(l) == 1:
                #     k = ""
                #     q = ""
                #     # call functionality to handle issues
                #     self.processRequest(l[0], q, k)

                # else:  # bug: some issues do not have request responses.
                #     k = ""
                #     q = ""
                #     # call functionality to handle issues
                #     self.processRequestWithoutRR(q, k)

    def processRequest(self, requestResponse, multipartOne, MulitpartTwo):

        r = requestResponse

        # get request data and convert to string
        requestDetail = r.getRequest()

        fName = self.m.getIssueName()  # retrive issue name
        print("[+] Finding Name: [%s]" % self.m.getIssueName())
        url = self._helpers.analyzeRequest(r).getUrl()
        print("[+] Finding sent to report: [%s] " % str(url))

        # GET request details & Markers
        requestMarkers = r.getRequestMarkers()
        reqMarkersParsed = self.parseMarkers(requestMarkers)

        # converts & Prints out the entire request as string
        requestData = self._helpers.bytesToString(requestDetail)

        # GET response details & Markers

        responseDetail = r.getResponse()
        responseMarkers = r.getResponseMarkers()

        resMarkersParsed = self.parseMarkers(responseMarkers)

        # converts & Prints out the entire request as string
        responseData = self._helpers.bytesToString(responseDetail)

        # base64 encode requestresponses:
        enRequest = requestData.encode('base64', 'strict')
        enResponse = responseData.encode('base64', 'strict')

        # Handles issues with more than on request and response to the issue eg: 1/2, 2/2
        multipart = str(multipartOne) + "/" + str(MulitpartTwo)

        Cbuffer = ""
        # prepare to write out to file
        finding = [fName, url, enRequest, reqMarkersParsed,
                   enResponse, resMarkersParsed, multipart, Cbuffer]

        # write out to file
        self.report(finding)

        if multipartOne != "":
            print("[!] Part %s added to report" % multipart)

        else:
            print("[!] Finding added to report.")

    def processRequestWithoutRR(self, multipartOne, MulitpartTwo):

        fName = self.m.getIssueName()  # retrive issue name
        print("[+] Finding Name: ", self.m.getIssueName())
        url = self.m.getUrl()
        print("[+] Finding sent to report: [%s] " % str(url).encode('utf-8'))

        #  converts & Prints out the entire request as string  # certifcates
        requestData = self.m.getIssueDetail()

        if requestData is not None:
            # removes html as the scanissue is all in html
            cleaner = re.compile('<.*?>')
            cleanReqData = re.sub(cleaner, '\n', requestData)
            # this could still be tidied to produce better output.
            cleanRequestData = cleanReqData.replace('&nbsp', '')

            # handle none unicode
            cleanRequestData = cleanRequestData.encode('utf-8')

            # base64 encode requestresponses:
            enRequest = cleanRequestData.encode('base64', 'strict')

        else:
            enRequest = None

        # Handles issues with more than on request and response to the issue eg: 1/2, 2/2
        multipart = str(multipartOne) + "/" + str(MulitpartTwo)

        Cbuffer = ""
        # prepare to write out to file
        finding = [fName, url, enRequest, "", "", "", multipart, Cbuffer]

        # write out to file
        self.report(finding)

        if multipartOne != "":
            print("[!] Part %s added to report" % multipart)

        else:
            print("[!] Finding added to report.")

    # takes an array of markers and cycles through them to collect the int coordinates.
    def parseMarkers(self, markers):

        markersOut = []
        c = 0

        if len(markers) >= 1:
            for i in range(0, len(markers)):
                c = c + 1
                # print "[+] Marker Pair %s:" % str(c)
                start = markers[i][0]
                # print "[+] start: ", start
                end = markers[i][1]
                # print "[+] end: ", end
                setM = [c, start, end]
                markersOut.append(setM)

        return markersOut

    def report(self, finding):

        f = open(self.c, "a")
        report = csv.writer(f)
        report.writerow(finding)
        f.close()

    def createReport(self):
        # Until I work out a different way specify a path for the report here
        # uncomment to find out the path of the outfile
        path = os.getcwd()
        # potential for date to add in to the name...
        outfile = self.url + ".csv"
        report = str(path)+"/"+outfile
        self.c = report

        # clear report
        c = open(self.c, "w")
        c.close()

        return self.c

    # API hook...
    def getHttpMessages(self):
        return [self.m]

    # Actions on menu click...
    # def actionPerformed(self, actionEvent):
    #     print("*" * 60)
    #     try:
    #         self.getSelectedScanIssues()
    #     except:
    #         tb = traceback.format_exc()
    #         print(tb)

    # Create Menu
    # def createMenuItems(self, ctxMenuInvocation):

    #     self.ctxMenuInvocation = ctxMenuInvocation
    #     return [self.menuItem]
