"""
This module generates example IoT networks based on topology type and vulnerabilities.
"""

from Network import *
from Harm import *
from SecurityEvaluator import *
import math
import random
import PyDev
CONST_DIMENSIONS = (50, 50)


"""
-------------------------------------------------------------------------
Create network with vulnerabilities for the example IoT network.
-------------------------------------------------------------------------
"""

# study this part of the code and change wifi to bluetooth

def createWiFi():
    #Create a Ipod with two vulnerabilities
    ipod = iot('ipod')
    print("coordinate:", ipod.coorX, ipod.coorY)
    ipod.subnet.append('wifi')
    v1 = vulNode('CVE-2009-2206')
    v1.createVuls(ipod, 10.0, 1) #CVSS base score: 10.0
    v2 = vulNode('CVE-2009-0385')
    v2.createVuls(ipod, 10.0, 1) #CVSS base score: 9.3
    v2.thresholdPri(ipod, 1)
    v2.terminalPri(ipod, 1)

    #Create a camera with one vulnerability
    cam = iot('cam')
    print("coordinate:", cam.coorX, cam.coorY)
    cam.subnet.append('wifi')
    v3 = vulNode('CVE-2013-4977')
    v3.createVuls(cam, 10.0, 1) #CVSS base score: 10.0
    v3.thresholdPri(cam, 1)
    v3.terminalPri(cam, 1)

    #Create a tablet with three vulnerabilities
    tab = iot('tab')
    print("coordiante:", tab.coorX, tab.coorY)
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
    net.withinRange(ipod, tab)
    net.withinRange(cam, tab)
    net.withinRange(cam, ipod)


    
    #connect tv and cam to tab
    if(net.withinRange(ipod, tab) == 1):
        net.connectOneWay(ipod, tab)
    
    if(net.withinRange(cam, tab) == 1):
        net.connectOneWay(cam, tab)

    if(net.withinRange(ipod, tab) == 1):
        net.connectOneWay(cam, ipod)

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
    net = createWiFi()

    #Create HARM and compute attack paths
  
    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 3)
    h.model.printPath()
    h.model.printAG()
    
    #Calculate security metric: attack impact
    # attackImpactAnalysis(net, 3)
    rw = PyDev.RandomWalk(3, CONST_DIMENSIONS, velocity=1,
                          distance=1, border_policy='reflect')
    #Calculate security metric: risk
    print(rw)
    





