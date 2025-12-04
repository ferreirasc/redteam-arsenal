import xml.etree.ElementTree as etree
import shutil
import os

first = True
mainTree = None
report = None

for fileName in os.listdir("."):
    if fileName.endswith(".nessus"):
        print(":: Parsing", fileName)

        if first:
            mainTree = etree.parse(fileName)
            report = mainTree.find('Report')
            report.attrib['name'] = 'Merged Report'
            first = False
        else:
            tree = etree.parse(fileName)
            for host in tree.findall('.//ReportHost'):
                host_name = host.attrib.get('name')
                existing_host = report.find(f".//ReportHost[@name='{host_name}']")

                if existing_host is None:
                    print(f"adding host: {host_name}")
                    report.append(host)
                else:
                    for item in host.findall('ReportItem'):
                        port = item.attrib.get('port')
                        pluginID = item.attrib.get('pluginID')

                        query = f"ReportItem[@port='{port}'][@pluginID='{pluginID}']"
                        if existing_host.find(query) is None:
                            print(f"adding finding: {port}:{pluginID}")
                            existing_host.append(item)

        print(":: => done.")

# Output folder handling
if os.path.exists("nss_report"):
    shutil.rmtree("nss_report")

os.mkdir("nss_report")

mainTree.write("nss_report/report.nessus", encoding="utf-8", xml_declaration=True)

