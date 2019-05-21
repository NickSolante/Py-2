"""
This module generates example IoT networks based on topology type and vulnerabilities.
"""

from Network import *
from Harm import *
from SecurityEvaluator import *
import math
import random
import PyDev
import time
import csv
import matplotlib.pyplot as plt
CONST_DIMENSIONS = (50, 50)


"""
-------------------------------------------------------------------------
Create network with vulnerabilities for the example IoT network.
-------------------------------------------------------------------------
"""

# study this part of the code and change wifi to bluetooth

def createWiFi(time):
    #Create a Ipod with two vulnerabilities
    i = time
    ipod = iot('ipod')
    ipod.changeCoordinate()
    print("coordinate:", ipod.Xcoor[i], ipod.Ycoor[i])
    ipod.subnet.append('wifi')
    v1 = vulNode('CVE-2009-2206')
    v1.createVuls(ipod, 10.0, 1) #CVSS base score: 10.0
    v2 = vulNode('CVE-2009-0385')
    v2.createVuls(ipod, 10.0, 1) #CVSS base score: 9.3
    v2.thresholdPri(ipod, 1)
    v2.terminalPri(ipod, 1)

    #Create a camera with one vulnerability
    cam = iot('cam')
    cam.changeCoordinate()
    print("coordinate:", cam.Xcoor[i], cam.Ycoor[i])
    cam.subnet.append('wifi')
    v3 = vulNode('CVE-2013-4977')
    v3.createVuls(cam, 10.0, 1) #CVSS base score: 10.0
    v3.thresholdPri(cam, 1)
    v3.terminalPri(cam, 1)

    #Create a tablet with three vulnerabilities
    tab = iot('tab')
    tab.changeCoordinate()
    print("coordiante:", tab.Xcoor[i], tab.Ycoor[i])
    tab.subnet.append(['wifi', 'zb'])
    v4 = vulNode('tb_v1')
    v4.createVuls(tab, 10.0, 1)
    v5 = vulNode('tb_v2')
    v5.createVuls(tab, 10.0, 2)
    v6 = vulNode('tb_v3')
    v6.createVuls(tab, 10.0, 3)
    #The attacker needs to exploit both vulnerabilities to compromise the node
    tab.vul.connectOneWay(tab.vul.nodes[0], tab.vul.nodes[1])
    tab.vul.connectOneWay(tab.vul.nodes[1], tab.vul.nodes[2])
    v6.thresholdPri(tab, 1)
    v6.terminalPri(tab, 3)

    #Create a Wi-Fi network
    net = network()



    #connect tv and cam to tab
    if(net.withinRange(ipod, tab, i) == 1):
        net.connectOneWay(ipod, tab)
    else:
        net.disconnectTwoWays(ipod, tab)

    if(net.withinRange(cam, tab, i) == 1):
        net.connectOneWay(cam, tab)
    else:
        net.disconnectTwoWays(cam, tab)

    if(net.withinRange(ipod, tab, i) == 1):
        net.connectOneWay(cam, ipod)
    else:
        net.disconnectTwoWays(cam, ipod)

    # net.connectOneWay(cam, tab)

    #connect Ipod and cam to tab
    net.nodes.append(ipod)
    net.nodes.append(cam)
    net.nodes.append(tab)



    #Set the attacker as the start
    A = computer('attacker')
    A.setStart()
    #Link the attacker with Ipod and camera
    for node in net.nodes:
        if node.name in ['ipod', 'cam']:
            A.con.append(node)
        else:
            node.setEnd()

    net.nodes.append(A)
    net.constructSE()
    net.printNetWithVul()

    return net



if __name__ == '__main__':
    
    aim = []
    aPaths = []
    for i in range(10):
        net = createWiFi(i)

    #Calculate security metric: attack impact
        j = attackImpactAnalysis(net, 3)
        print("j: ", j)
        if(j == 0):
            aim.append(0)
            aPaths.append(0)
            continue
        else:
            aim.append(j[0])
            aPaths.append(j[1])

    # with open('impact.csv', 'w', newline='', encoding='utf-8') as csvFile:
    #         writer = csv.writer(csvFile)
    #         print(aim)
    #         writer.writerow(map(lambda x: [x], aim))
    # csvFile.close()
    fig = plt.figure(figsize=(6,4))
    sub1 = fig.add_subplot(2, 2, 1, title='aim', ylabel='Attack Impact Value', xlabel='Time Point')
    sub1.set_title('aim')
    sub1.plot(aim)

    plt.subplot(211)
    plt.plot(aim)
    plt.xlabel('Time Point')
    plt.ylabel('Attack Impact Value')
    plt.title('Aim')

    #plt.show()
    plt.subplot(212)
    plt.plot(aPaths)
    plt.xlabel('Time Point')
    plt.ylabel('Number of Attack Paths')

    plt.show()







