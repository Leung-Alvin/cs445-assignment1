import networkx as nx
import matplotlib.pyplot as plt
import math
from treelib import Tree
import os
import json
import random
#random.seed(681)
import copy
import re
#import pandas as pd

#from graphviz import Source

class Packet:
    def __init__(self, payload, node, start, end, distance):
        self.payload = payload
        self.node = node
        self.start = start
        self.end = end
        self.distance = distance
    def __str__(self):
        return f"{self.payload}, {self.node}, {self.start}, {self.end}, {self.distance}"
    
    def set_node(self,new_node):
        self.node = new_node

    def set_start(self,new_start):
        self.start = new_start

    def set_end(self,new_end):
        self.end = new_end

    def set_distance(self,new_distance):
        self.distance = new_distance

    def get_distance(self):
        return self.distance
class Node:
    def __init__(self, ip_addr, role, packets, prediction,total):
        self.ip_addr = ip_addr
        self.role = role
        self.packets = packets
        self.prediction = prediction
        self.total =  total

    def __str__(self):
        return f"{self.ip_addr} ({self.role})"

    def generate_packets(self,num_packets):
        copy = Packet(self.role,None,None,None,0)
        self.packets = [Packet(self.role,None,None,None,0) for _ in range(num_packets)]

    def get_counts(self):
        attack_count = 0 
        normal_count = 0 
        router_count = 0
        for packet in self.packets:
            print("victim packet, ",packet)
            if packet.payload == 'a':
                attack_count+=1
            elif packet.payload == 'n':
                normal_count+=1
            elif packet.payload == 'r':
                router_count+=1

        return {"a":attack_count,"n":normal_count, "r":router_count}
    def total_packets(self):
        return self.total




def generate_treelib_tree(max_height, branching_factor=2,attacker_count=0,normal_count=1):
    tree = Tree()
    id = 2
    root_id = 2 
    tree.create_node(f"Victim .{id}", root_id, data=Node(f"{id}","v", packets=[], prediction={},total= 0))
    id+=1
    def add_children(parent_id, current_depth,id):
        if current_depth >= max_height:
            return id
        
        for _ in range(branching_factor):
            tree.create_node(tag=f"Router .{id}", identifier=id, parent=parent_id, data=Node(f".{id}",role="r",packets=[],prediction={},total=0))
            new_id = id 
            id+=1 
            id = add_children(new_id, current_depth+1, id)
        return id

    add_children(root_id, 0,id)
    leaf_nodes = [node for node in tree.all_nodes() if node.is_leaf()]
    random.shuffle(leaf_nodes)
    for i in range(attacker_count):
        # print("tag ",leaf_nodes[i].tag)
        # print("identifier ",leaf_nodes[i].identifier)
        # print("data ", leaf_nodes[i].data.role)
        leaf_nodes[i].tag = leaf_nodes[i].tag.replace("Router", "Attacker")
        leaf_nodes[i].data.role = "a"
        #print("tag ",leaf_nodes[i].tag)
        #print("identifier ",leaf_nodes[i].identifier)
        #print("data ", leaf_nodes[i].data.role)
    for i in range(normal_count):
        leaf_nodes[i+attacker_count].tag = leaf_nodes[i+attacker_count].tag.replace("Router","Normal")
        leaf_nodes[i+attacker_count].data.role = "n"
    for node in leaf_nodes:
        if node.data.role == 'r':
            node.tag = node.tag.replace("Router", "Delete")
            node.data.role = "d"
   # for node in leaf_nodes:
   #     print("tag",node.tag)
   #     print("identifier",node.identifier)
   #     print("data",node.data.ip_addr)
    #for node in list(tree.all_nodes()):
    #    if "Delete" in node.tag:
    #        tree.remove_node(node.identifier)
    leaf_nodes = [node for node in tree.all_nodes() if node.is_leaf()]
    targets = [x.identifier for x in leaf_nodes if 'Attacker' in x.tag or 'Normal' in x.tag]
    nodes_to_keep = set()
    for target_id in targets:
        node = tree.get_node(target_id)
        while node:
            nodes_to_keep.add(node.identifier)
            node = tree.parent(node.identifier)
    identifiers = [x.identifier for x in tree.all_nodes()]
    for node in list(tree.all_nodes()):
        if node.identifier not in nodes_to_keep:
            try:
                tree.remove_node(int(node.identifier))
            except:
                pass
    return tree

def display_node_data(tree):
    for node in tree.all_nodes():
        packets = node.data.packets
        print("packets from ",node.tag)
        for packet in packets:
            print(packet)


def generate_leaf_packets(tree,rate,normal_rate):
    normal_rate = normal_rate
    attacker_rate = normal_rate*rate
    leaf_nodes = [node for node in tree.all_nodes() if node.is_leaf()]
    for node in leaf_nodes:
        if node.data.role == "a":
            node.data.generate_packets(num_packets=attacker_rate)
        elif node.data.role == "n":
            node.data.generate_packets(num_packets=normal_rate)

def move_packets_up(tree, p):
    for node in tree.all_nodes():
        if node.data.packets:
            marked_packets = node.data.packets
            if node.data.role == 'r':
                marked_packets = []
                for packet in node.data.packets:
                    #print(packet)
                    if packet is not None:
                        if random.random() < p:
                            copied_packet = copy.deepcopy(packet)
                            copied_packet.set_node(node.tag)
                            marked_packets.append(copied_packet)
                        else:
                            marked_packets.append(packet)
            orig = tree.parent(node.identifier).data.packets
            merged = orig + marked_packets
            shuffled = random.sample(merged,len(merged))
            shuffled = [x for x in shuffled if x is not None]
            #print(tree.parent(node.identifier))
            tree.parent(node.identifier).data.packets = shuffled
            node.data.packets = []
            
def reconstruct(tree,tree_height,true_paths):
    unshuffled = tree.get_node(tree.root).data.packets

    packets = random.sample(unshuffled, len(unshuffled))
    packets = tree.get_node(tree.root).data.packets

    for packet in packets:
        if packet.node is not None and packet.payload =='a':
            #if packet.node is not None and packet.payload == 'a':
            if packet.node in tree.get_node(tree.root).data.prediction:
                tree.get_node(tree.root).data.prediction[packet.node]+=1 
            else:
                tree.get_node(tree.root).data.prediction[packet.node]=1 
            tree.get_node(tree.root).data.total+=1
        if get_path(tree,tree_height) in true_paths:
            break
    tree.show()
    print(get_path(tree,tree_height))


def get_path(tree,tree_height):
    dictionary = tree.get_node(tree.root).data.prediction
    sorted_keys = sorted(dictionary, key=dictionary.get, reverse=True)
    return sorted_keys[0:tree_height-1]

            
def edge_reconstruct(tree,tree_height,true_paths):
    unshuffled = tree.get_node(tree.root).data.packets

    packets = random.sample(unshuffled, len(unshuffled))
    packets = tree.get_node(tree.root).data.packets

    G =  nx.Graph()
   # id = 2
   # root_id = 2 
   # G.create_node(f"Victim .{id}", root_id, data=Node(f"{id}","v", packets=[], prediction={},total= 0))
   # id+=1

    for packet in packets:
        #if packet.payload =='a' and packet.start is not None:
        if packet.start is not None:
            if packet.distance == 0:
                if packet.start in G:
                    G.add_edge(packet.start,"Victim .2",weight=0)
                else:
                    G.add_node(packet.start)
                    G.add_edge(packet.start,"Victim .2",weight=0)
            else:
                if packet.start in G and packet.end in G:
                    G.add_edge(packet.start, packet.end, weight=packet.distance)
                elif packet.start not in G and packet.end in G:
                    G.add_node(packet.start)
                    G.add_edge(packet.start, packet.end, weight=packet.distance)
                elif packet.start in G and packet.end not in G:
                    G.add_node(packet.end)
                    G.add_edge(packet.start, packet.end, weight=packet.distance)
                else:
                    G.add_node(packet.start)
                    G.add_node(packet.end)
                    G.add_edge(packet.start, packet.end, weight=packet.distance)


                    
    #print(get_path(tree,tree_height))
    tree.show()
    nx.draw(G,with_labels=True)
    plt.savefig("test.png")

def simulation_round(tree,attack_rate,tree_height,protocol,marking_prob,normal_rate,true_paths):
    generate_leaf_packets(tree, attack_rate,normal_rate)
    for _ in range(tree_height):
        move_packets_up(tree,marking_prob)
    reconstruct(tree, tree_height,true_paths)
    #display_node_data(tree)
    tree.get_node(tree.root).data.packets = []

    #print("Total Packets Received by Victim: ",tree.get_node(tree.root).data.total)
    #print("Prediction by Victim: ", get_path(tree,tree_height))
    #print('\n')
    #return (total_packets, path)

def edge_move_packets_up(tree, p):
    for node in tree.all_nodes():
        if node.data.packets:
            marked_packets = node.data.packets
            if node.data.role == 'r':
                marked_packets = []
                for packet in node.data.packets:
                    #print(packet)
                    if packet is not None:
                        copied_packet = copy.deepcopy(packet)
                        if random.random() < p:
                            copied_packet.set_start(node.tag)
                            copied_packet.set_distance(0)
                            marked_packets.append(copied_packet)
                        else:
                            if copied_packet.get_distance() == 0:
                                copied_packet.set_end(node.tag)

                            copied_packet.set_distance(copied_packet.get_distance()+1)
                            marked_packets.append(copied_packet)
            orig = tree.parent(node.identifier).data.packets
            merged = orig + marked_packets
            shuffled = random.sample(merged,len(merged))
            shuffled = [x for x in shuffled if x is not None]
            #print(tree.parent(node.identifier))
            tree.parent(node.identifier).data.packets = shuffled
            node.data.packets = []

def edge_simulation_round(tree,attack_rate,tree_height,protocol,marking_prob,normal_rate,true_paths):
    generate_leaf_packets(tree,attack_rate,normal_rate)

    for _ in range(tree_height):
        edge_move_packets_up(tree,marking_prob)
        display_node_data(tree)
    edge_reconstruct(tree, tree_height,true_paths)
    tree.get_node(tree.root).data.packets = []

def path_to_root(tree, node_id):
    path = []
    node = tree.get_node(node_id)
    while node:
        path.append(node.identifier)
        node = tree.parent(node.identifier)
    reverse = path[::-1]
    trimmed = reverse[1:-1]
    return_list = []
    for item in trimmed:
        return_list.append('Router .'+str(item))
    return return_list

def get_attacker_ids (tree):
    return [x.identifier for x in tree.all_nodes() if "Attacker" in x.tag]
def ns_main_single_attack():

    #attacker_count = input("Enter number of attackers: ")
    #attacker_count = int(attacker_count)    
    #if attacker_count > 3:
    #    print("Too many attackers.")
    #    return 
    #marking_prob = input("Enter probability of marking: ")
    #marking_prob = float(marking_prob)
    #if marking_prob > 1 or marking_prob < 0:
    #    print("Bad probability.")
    #    return

    #attacker_rate = input("Enter attack rate: ")
    #attack_rate = float(rate)
    
    protocol = 'ns'
    tree_height = 6 
    branching_factor = 3
    attacker_count = 1 
    marking_prob = 0.2
    normal_count = 1
    normal_rate = 10 
    ps = [0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.55,0.6,0.65,0.7,0.75,0.8,0.85,0.9,0.95]
    xs = [10,100,1000]


    values = []
    for x in xs:
        cs = []
        for p in ps:
            avg = []
            for i in range(10):
                tree = generate_treelib_tree(tree_height, branching_factor, attacker_count=attacker_count, normal_count=normal_count )
                attacker_ids = get_attacker_ids(tree)
                true_paths = []
                for attacker_id in attacker_ids:
                    true_paths.append(path_to_root(tree,attacker_id))
                #print("true_paths",true_paths)
                round = 0
                total = 0
                prediction=[]
                while(prediction not in true_paths):
                    #print('total before',total)
                    simulation_round(tree,x,tree_height,protocol,p,normal_rate,true_paths)
                    prediction = get_path(tree,tree_height) 
                    total += tree.get_node(tree.root).data.total
                    #print('total after', total)
                avg.append(total)
            average = sum(avg)/len(avg)
            cs.append(math.log(average))
        values.append(cs)


    print(values)
    plt.plot(ps,values[0], label="10")
    plt.plot(ps,values[1], label="100")
    plt.plot(ps, values[2], label="1000")
    plt.xlabel("Probability")
    plt.ylabel("Log(Num Packets)")
    plt.title("Log(Number of Packets) vs Probability Node Sampling")
    plt.legend()
    plt.savefig("ns_sa.png")
    plt.clf()

def ns_main_double_attack():
    protocol = 'ns'
    tree_height = 6 
    branching_factor = 3
    attacker_count = 2 
    marking_prob = 0.2
    normal_count = 1
    normal_rate = 10 
    ps = [0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.55,0.6,0.65,0.7,0.75,0.8,0.85,0.9,0.95]
    xs = [10,100,1000]


    values = []
    for x in xs:
        cs = []
        for p in ps:
            avg = []
            for i in range(10):
                tree = generate_treelib_tree(tree_height, branching_factor, attacker_count=attacker_count, normal_count=normal_count )
                attacker_ids = get_attacker_ids(tree)
                true_paths = []
                for attacker_id in attacker_ids:
                    true_paths.append(path_to_root(tree,attacker_id))
                #print("true_paths",true_paths)
                round = 0
                total = 0
                prediction=[]
                while(prediction not in true_paths):
                    #print('total before',total)
                    simulation_round(tree,x,tree_height,protocol,p,normal_rate,true_paths)
                    prediction = get_path(tree,tree_height) 
                    total += tree.get_node(tree.root).data.total
                    #print('total after', total)
                avg.append(total)
            average = sum(avg)/len(avg)
            cs.append(math.log(average))
        values.append(cs)


    print(values)
    plt.plot(ps,values[0], label="10")
    plt.plot(ps,values[1], label="100")
    plt.plot(ps, values[2], label="1000")
    plt.xlabel("Probability")
    plt.ylabel("Log(Num Packets)")
    plt.title("Log(Number of Packets) vs Probability Node Sampling")
    plt.legend()
    plt.savefig("ns_da.png")
    plt.clf()

def es_main_single_attack():
    protocol = 'es'
    tree_height = 6 
    branching_factor = 3
    attacker_count = 2 
    marking_prob = 0.2
    normal_count = 1
    normal_rate = 10 
    ps = [0.05,0.1,0.15,0.2,0.25,0.3,0.35,0.4,0.45,0.5,0.55,0.6,0.65,0.7,0.75,0.8,0.85,0.9,0.95]
    xs = [10,100,1000]


    values = []
    for x in xs:
        cs = []
        for p in ps:
            avg = []
            for i in range(1):
                tree = generate_treelib_tree(tree_height, branching_factor, attacker_count=attacker_count, normal_count=normal_count )
                attacker_ids = get_attacker_ids(tree)
                true_paths = []
                for attacker_id in attacker_ids:
                    true_paths.append(path_to_root(tree,attacker_id))
                #print("true_paths",true_paths)
                round = 0
                total = 0
                prediction=[]
                edge_simulation_round(tree,x,tree_height,protocol,p,normal_rate,true_paths)
               # while(prediction not in true_paths):
               #     #print('total before',total)
               #     edge_simulation_round(tree,x,tree_height,protocol,p,normal_rate,true_paths)
               #     prediction = get_path(tree,tree_height) 
               #     total += tree.get_node(tree.root).data.total
               #     #print('total after', total)
               # avg.append(total)
            average = sum(avg)/len(avg)
            cs.append(math.log(average))
        values.append(cs)


    print(values)
    plt.plot(ps,values[0], label="10")
    plt.plot(ps,values[1], label="100")
    plt.plot(ps, values[2], label="1000")
    plt.xlabel("Probability")
    plt.ylabel("Log(Num Packets)")
    plt.title("Log(Number of Packets) vs Probability Node Sampling")
    plt.legend()
    plt.savefig("ns_da.png")
    plt.clf()
if __name__ == "__main__":
    #ns_main_single_attack()
    #ns_main_double_attack()
    es_main_single_attack()
