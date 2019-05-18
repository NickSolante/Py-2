"""
This module contains node objects
"""

# from random import *
import random
from math import *
import PyDev
import time

class node(object):
    """
    Create basic node object.
    """
    
    def __init__(self, name, diam = 20):
        self.name = name
        print(name)
        #Set connections 
        self.con = []
        #Store lower layer info    
        self.child = None
        #Store a list of parent nodes
        self.parent = None
        #Set default value of start/end
        self.isStart = False
        self.isEnd = False
        self.subnet = []
        # set coordinates for random initial area
    #Set the node as normal/start/end
    def setStart(self):
        self.isStart = True
    def setNormal(self):
        self.isStart = False
        self.isEnd = False
    def setEnd(self):        
        self.isEnd = True
    #Check whether the node is leaf or not
    def isLeaf(self):
        return (len(self.con) is 1)
    
    
class iot(node):
    """
    Create IoT device object. 
    """
    def __init__(self, name):
        super(iot, self).__init__(name)
        self.vul = None
        self.type = None
        self.coorX = random.randint(1, 50)
        self.coorY = random.randint(1, 50)
        self.dimension = (self.coorX, self.coorY)
        self.effDiam = 20
        self.Xcoor = [self.coorX]
        self.Ycoor = [self.coorY]


    def changeCoordinate(self):
        rw = PyDev.RandomWalk(3, self.dimension, velocity=1,
                              distance=1, border_policy='reflect')
        time = 0
        for i in rw:
            self.dimension = i[1]
            self.coorX = self.dimension[0]
            self.coorY = self.dimension[1]
            self.Xcoor.append(self.coorX)
            self.Ycoor.append(self.coorY)
            time += 1
            if time > 8:
                break

    def checkNodeInCons(self, node1, node2):
        """
        Check whether the node1 is in the connections of node2.
        """
        for temp in node2.con:
            if node1.name == temp.name:
                return 1
        
        return 0
    
    def checkNodeInList(self, list):
        """
        Check whether the node is in the list or not.
        """
        for temp in list:
            if self.name == temp.name:
                return True 
            
        return False


class computer(node):
    """
    Create computer object.
    Could be used for the attacker node.
    """
    def __init__(self, name):
        super(computer, self).__init__(name, diam = 60)
        self.vul = None
        self.type = None
            
    
