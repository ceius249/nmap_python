import nmap
import requests

class Location:
    def __init__(self, ipAddress):
        self.infomation = requests.get(f"http://ip-api.com/json/{ ipAddress }").json()
    
    def getStatus(self):
        if(self.infomation["status"] == "success"):
            return True
        else:
            return False
    
    def getCountry(self):
        if(self.getStatus()):
            return self.infomation["country"]
        else:
            return ""
    def getCountryCode(self):
        if(self.getStatus()):
            return self.infomation["countryCode"]
        else:
            return ""

    def getCity(self):
        if(self.getStatus()):
            return self.infomation["city"]
        else:
            return ""
    
    def getDetailLocation(self):
        if(self.getStatus()):
            return {
                "country": self.getCountry(),
                "country_code": self.getCountryCode(),
                "city": self.getCity(),
            }
            
    def __str__(self):
        if(self.getStatus()):
            return f"{ self.getCity() }, { self.getCountry() }"
        else: 
            return ""


def appendMaxRate(maxRate):
    if (maxRate != None):
        return f" --max-rate { maxRate }"
    else:
        return ""

def appendMinRate(minRate):
    if (minRate != None):
        return f" --min-rate { minRate }"
    else:
        return ""


class IPInfo:
    def __init__(
                    self,
                    hostname = "127.0.0.1",
                    ports = None,
                    arguments = "",
                    minRate = None,
                    maxRate = None,
                ):
        self.hostname = hostname
        self.ports = ports
        self.arguments = arguments + "-sV -Pn"
        self.minRate = minRate
        self.maxRate = maxRate
        self.location = Location(self.hostname)
        self._nmap = nmap.PortScanner()
        self.rawDataNmap = self._nmap.scan(
                                            self.hostname, 
                                            ports = self.ports, 
                                            arguments = "-O -sV -Pn" + appendMaxRate(self.minRate) + appendMaxRate(self.maxRate), 
                                            sudo = True,
                                          )

    def getCommandLine(self):
        return self._nmap.command_line()

    def getHostStatus(self):
        status = self.rawDataNmap["nmap"]["scanstats"]["uphosts"]
        if (status == "1"):
            return True

    def getOpenPorts(self):
        if (self.getHostStatus()):
            listPorts = []
            openPorts = self.rawDataNmap["scan"][self.hostname]["tcp"]

            for openPort in openPorts:
                listPorts.append(str(openPort))
        
            return listPorts  
        else:
            return ""
    def getDeviceType(self):
        if (self.getHostStatus()):
            return self.rawDataNmap["scan"][self.hostname]["osmatch"][0]["name"]
        else:
            return ""
    
    def getLocation(self):
        return self.location.getCountry()

    def getIPInfo(self):
        return {
            "ip" : self.hostname,
            "port_info": self.getOpenPorts(),
            "device_type": self.getDeviceType(),
            "location": self.getLocation(),
            "metadata": "",
        }
    
    def getPortStatus(self, port):
        state = self.rawDataNmap["scan"][self.hostname]["tcp"][port]["state"]
        if ( state == "open"):
            return True
    
    def getPortNumber(self, port):
        return port

    def getService(self, port):
        return self.rawDataNmap["scan"][self.hostname]["tcp"][port]["name"]
    
    def getProduct(self, port):
        return self.rawDataNmap["scan"][self.hostname]["tcp"][port]["product"]
    
    def getVersion(self, port):
        return self.rawDataNmap["scan"][self.hostname]["tcp"][port]["version"]

    def getRawData(self, port):
        return {
            "port_number" : self.getPortNumber(port),
            "service" : self.getService(port),
            "product" : self.getProduct(port),
            "version" : self.getVersion(port),
            "rawdata" : "",
        }

    def getOnePortInfo(self, port):
        if (self.getPortStatus(port)):
            return self.getRawData(port)

    def listDetailPorts(self):
        ports = self.getOpenPorts()
        detailPortDict = {}

        for port in ports:
            detailPortDict[port] = self.getOnePortInfo(int(port))

        return detailPortDict

def scan_result(hostname):
    result = IPInfo(hostname)
    return {
        hostname : {
            "ip_info": result.getIPInfo(),
            "port_info": result.listDetailPorts(),
            "location": result.location.getDetailLocation(),
        }
    }


def main():
    # print(IPInfo(hostname = "127.0.0.1").getCommandLine())
    # print(IPInfo(hostname = "167.71.28.179").getIPInfo())
    # print(IPInfo(hostname = "167.71.28.179").getOnePortInfo())
    print(scan_result("167.71.28.179"))
    
    # Cau truc cua scan_result
    # {
    #     '167.71.28.179': 
    #     {
    #         'IPInfo': 
    #         {
    #             'IP': '167.71.28.179', 
    #             'PortInfo': ['5357'], 
    #             'DeviceType': 'AVtech Room Alert 26W environmental monitor', 
    #             'Location': 'United States', 
    #             'Metadata': ''
    #         }, 
    #         'PortInfo': 
    #         {
    #             '5357': 
    #             {
    #                 'PortNumber': 5357, 
    #                 'Service': 'http', 
    #                 'Product': 'Microsoft HTTPAPI httpd', 
    #                 'Version': '2.0', 
    #                 'RawData': ''
    #             }
    #         }, 
    #         'Location': 
    #         {
    #             'Country': 'United States', 
    #             'CountryCode': 'US', 
    #             'City': 'North Bergen'
    #         }
    #     }
    # }

if __name__ == "__main__":
    main()