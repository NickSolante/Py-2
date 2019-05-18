"""
This module contains network object and relevant functions.
"""

from Node import *
from Topology import *
import copy
import math
import time


class network(object):
    """
    Create network object.
    """

    def __init__(self):
        # Initialize node list
        self.nodes = []
        # Initialize start and end points
        self.s = None
        self.e = None
        # Initialize subnets
        self.subnets = []
        # Initialize vulnerability list which contains all node vulnerabilities
        self.vuls = []

    def copyNet(self):
        """
        Copy the network to a network.
        """

        temp = network()
        temp = copy.deepcopy(self)

        return temp

    def constructSE(self):
        """
        Set the start and end in the network.
        """
        self.s = node('S-')
        self.e = node('E-')

        for n in self.nodes:
            if n.isStart:
                self.s.con.append(n)
            if n.isEnd:
                n.con.append(self.e)

    def connectOneWay(self, node1, node2):
        """
        Connect node1 to node2 in the network.
        """
        # no self connection
        if node1 is node2:
            return None
        # connect node1 to node2
        # if(self.withinRange(node1, node2) != 1):
        #     return None

        # else:

        if (node2 not in node1.con):
            node1.con.append(node2)

    def connectTwoWays(self, node1, node2):
        """
        Connect node1 with node2 in the network.
        """

        # no self connection
        if node1 is node2:
            return None
        # create connections
        if (node2 not in node1.con):
            node1.con.append(node2)
        if (node1 not in node2.con):
            node2.con.append(node1)

    # function checks if they are within range
    def withinRange(self, node1, node2, timeinsec):
        i = timeinsec
        dist = math.sqrt((node2.Xcoor[i] - node1.Xcoor[i])**2 + (node2.Ycoor[i] - node1.Ycoor[i])**2)
        print("the distance", dist)
        
        if (dist > node1.effDiam):
            print("Connection Failed")
            return -1

        else:
            print("Connection was Successful")
            return 1

    # checks if each node is whithin range of eachother

    def checkNodesRange(self):
        result = 0

        for node_x in self.nodes:
            for node_y in self.nodes:
                if node_x.name == node_y.name:
                    continue
                else:
                    result = self.withinRange(node_x, node_y)

        if result < len(self.nodes):
            return False
        else:
            return True

    def checkNodesRangeAttack(self):
        for x in range(len(nodes)):
            if x is len(nodes) - 1:
                break
            else:
                withinRange(nodes[len(nodes)-1], nodes[x])

    def disconnectTwoWays(self, node1, node2):
        """
        Disconnect node1 and node2 in the network.
        """
        if node2 in node1.con:
            node1.con.remove(node2)
        if node1 in node2.con:
            node2.con.remove(node1)

    def printNet(self):
        """
        Print network.
        """
        for node in self.nodes:
            print(node.name+":", node.type)
            print("connect:",)
            for conNode in node.con:
                print(conNode.name)
            print("-----------------------------")
        return None

    def printNetWithVul(self):
        """
        Print network with vulnerabilities.
        """
        for node in self.nodes:
            #print(node.name+":", node.type, ",", node.sec)
            print(node.name + " : ")
            print("connect:",)
            for conNode in node.con:
                if conNode.name == 'S-' or conNode.name == 'E-':
                    print(conNode.name)
                else:
                    print(conNode.name)

            print("vulnerability:",)
            if node.vul is not None:
                for vul in node.vul.nodes:
                    #print(vul.name+":", vul.type, ",", vul.val)
                    print(vul.name+":", vul.val)
            print("------------------------------")

        return None
