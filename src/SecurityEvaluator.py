"""
This module conducts security analysis and generates SHARPE code from HARM as text file.
"""

from AttackGraph import *
from AttackTree import *
from Harm import *
import os
import math
from random import shuffle, uniform, expovariate
import numpy as np

#-------------------------------------------------------
#Compute maximum risk
#-------------------------------------------------------
def computeRisk(harm):
    """
    Compute risk for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    risk = []
    
    harm.model.calcRisk()
    
    for path in harm.model.allpath:
        pathRisk = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    #print(node.name, node.type, node.val)
                    pathRisk += node.val
        
        #print(pathRisk)
        risk.append(pathRisk)
        
    value = max(risk)
    return value

def riskAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        r = computeRisk(h)
    else:
        return 0
        
    return r


#-------------------------------------------------------
#Compute maximum return on attack
#-------------------------------------------------------
def computeReturnOnAttack(harm):
    """
    Compute risk for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    attackReturn = []
    
    harm.model.calcReturnOnAttack()
    
    for path in harm.model.allpath:
        pathReturn = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    #print(node.name, node.type, node.val)
                    pathReturn += node.val
        #print(pathReturn)
        attackReturn.append(pathReturn)
        
    value = max(attackReturn)
    
    return value


def returnOnAttackAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        r = computeReturnOnAttack(h)
    else:
        return 0
        
    return r


#-------------------------------------------------------
#Compute maximum attack impact
#-------------------------------------------------------

def computeAttackImpact(harm):
    """
    Compute attack impact for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    impact = []
    
    harm.model.calcImpact()
    print("=================================================")
    print("Print attack paths: \n")
    for path in harm.model.allpath:
        pathImpact = 0
        
        for node in path:
            print(node.name, end =' ')
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    print('(', node.val, ')', end = ' ')
                    pathImpact += node.val
        
        print("\n")
        impact.append(pathImpact)
        
    value = max(impact)
    
    print("Maximum attack impact is: ", value)
    
    return value


def attackImpactAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    h.model.printPath()
    h.model.printAG()
    
    if len(h.model.allpath) != 0:
        ai = computeAttackImpact(h)
    else:
        return 0
        
    return ai

#---------------------------------------------------------
#Compute minimum attack cost
#---------------------------------------------------------

def computeAttackCost(harm):
    """
    Compute attack cost for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    cost = []

    harm.model.calcCost()
    
    for path in harm.model.allpath:
        pathCost = 0
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                if node.val > 0:
                    #print(node.name, node.type, node.val)
                    pathCost += node.val
        
        cost.append(pathCost)
        
    value = min(cost)
    
    return value

def attackCostAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        ac = computeAttackCost(h)
    else:
        return 0
    
    return ac

#---------------------------------------------------------------
#Compute maximum attack success probability 
#---------------------------------------------------------------

def computeAttackPro(harm):
    """
    Compute attack success probability for HARM using attack graph as upper layer and attack tree as lower layer.
    """
    pro = []

    harm.model.calcPro()
    
    for path in harm.model.allpath:
        pathPro = 1
        for node in path:
            if node is not harm.model.s and node is not harm.model.e:
                #Exclude the attacker
                if node.val > 0:
                    pathPro *= node.val
        
        pro.append(pathPro)
        
    value = max(pro)
    
    return value

def attackProAnalysis(net, pri):

    h = harm()
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, pri)
    if len(h.model.allpath) != 0:
        pro = computeAttackPro(h)
    else:
        return 0
    
    return pro


#------------------------------------
#Compute the number of paths
#------------------------------------
def NP_metric(harm):
    
    value = len(harm.model.allpath)
    return value

#------------------------------------------
#Compute the mean of path lengths
#------------------------------------------
def MPL_metric(harm):

    sum_path_length = 0
    for path in harm.model.allpath:
        sum_path_length += int(len(path)-3)
        #print(sum_path_length)

    value = float(sum_path_length/len(harm.model.allpath))

    return value

#----------------------------------------
#Compute the mode of path lengths
#----------------------------------------
def MoPL_metric(harm):
    
    NP = []
    for path in harm.model.allpath:
        NP.append(int(len(path)-3))

    value = max(NP, key=NP.count)
    return value

#----------------------------------------------------------
#Compute the standard deviation of path lengths
#----------------------------------------------------------
def SDPL_metric(harm):

    sumation_DPL = 0
    MPL = MPL_metric(harm)
    #print(MPL)
    for path in harm.model.allpath:    
        sumation_DPL += float(len(path) - 3 - MPL)**2
        #print(sumation_DPL)

    value = math.sqrt(float(sumation_DPL / len(harm.model.allpath)))

    return value

#--------------------------------------
#Compute the shortest attack path
#--------------------------------------
def SP_metric(harm):

    SP=[]
    for path in harm.model.allpath:
        SP.append(int(len(path)-3))
    value = min(SP)
    return value

