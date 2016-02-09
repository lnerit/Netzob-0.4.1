# -*- coding: utf-8 -*-
#!/usr/bin/env python

import logging
import sys
import os
logging.basicConfig(level=logging.INFO)
sys.path.insert(0, "../../../netzob/src/")

from netzob.all import *


## Step 1
print "Step 1 --> Importing traces from PCAP files"

try:
    input("Protocol Vocabularly Modelling and Inference Phase -- > Press enter to continue")
except SyntaxError:
    pass

print "[++++++++++++++++++++ Import messages from a pcap ++++++++++++++++++++]\n"

msgs_session1 = PCAPImporter.readFile("/home/lenz/COMP588/Data Files/smtp.pcap").values()
#msgs_session2 = PCAPImporter.readFile("/home/lenz/COMP588/PRE/Project/projects/target_src_v1_session2.pcap").values()

msgs = msgs_session1 #+ msgs_session2

for m in msgs:
    print m


## Step 2
print "\nStep 2 --> Regrouping Messages in a symbol to do format partition based delimiter(#)"

try:
    input("Press enter to continue")
except SyntaxError:
    pass

print "\n[++++++++++++++++++++ Regroup messages in a symbol and do a format partitionment with a delimiter ('#' sounds interesting) ++++++++++++++++++++]\n"

symbol = Symbol(messages=msgs)

#Format.splitDelimiter(symbol, ASCII("#"))

print "[+] Symbol structure:"
print symbol._str_debug()
print "[+] Partitionned messages:"
print symbol


## Step 3
print "\nStep 3-7 --> Message Clustering according to the key fields identified. This phase involves\n"
print"                 -->Message clustering\n"
print"                 -->sequence alignment\n"
print"                 -->identifying field relations in the symbols\n"
print"                 -->Generating messsages according to definition of symbol\n"
try:
    input("Press enter to continue")
except SyntaxError:
    pass

print "\n[++++++++++++++++++++ Cluster according to a key field (the first one seems interesting) ++++++++++++++++++++]\n"

symbols = Format.clusterByKeyField(symbol, symbol.fields[0])
print "[+] Number of symbols after clustering: {0}".format(len(symbols))
print "[+] Symbol list:"
for keyFieldName, s in symbols.items():
    print "  * {0}".format(keyFieldName)

try:
    input("Press enter to continue")
except SyntaxError:
    pass

for s in symbols.values():
    ## Step 4
    print "\n[++++++++++++++++++++ Apply a format partitionment with a sequence alignment on the third field of the symbol: {0} ++++++++++++++++++++]\n".format(s.name)

    Format.splitAligned(s.fields[2], doInternalSlick=True)
    print "[+] Partitionned messages:"
    print s

    ## Step 5
    #try:
    #    input("Press enter to continue")
    #except SyntaxError:
    #    pass

    print "\n[++++++++++++++++++++ Find field relations in the symbol: {0} ++++++++++++++++++++]\n".format(s.name)

    rels = RelationFinder.findOnSymbol(s)
    if len(rels) == 0:
        print "[+] No relations found."
    else:
        print "[+] Relations found: "
        for rel in rels:
            print "  " + rel["relation_type"] + ", between '" + rel["x_attribute"] + "' of:"
            print "    " + str('-'.join([f.name for f in rel["x_fields"]]))
            p = [v.getValues()[:] for v in rel["x_fields"]]
            print "    " + str(p)
            print "  " + "and '" + rel["y_attribute"] + "' of:"
            print "    " + str('-'.join([f.name for f in rel["y_fields"]]))
            p = [v.getValues()[:] for v in rel["y_fields"]]
            print "    " + str(p)

		
            ## Step 6
           # try:
           #     input("Press enter to continue")
           # except SyntaxError:
           #     pass
            
            print "\n[++++++++++++++++++++Apply found relations in the symbol: {0} ++++++++++++++++++++]\n".format(s.name)
            rels[0]["x_fields"][0].domain = Size(rels[0]["y_fields"], factor=1/8.0)

    print "[+] Symbol structure:"
    print s._str_debug()


    ## Step 7
    #try:
    #    input("Press enter to continue")
    #except SyntaxError:
    #    pass

    print "\n[++++++++++++++++++++ Generate messages according to the definition of symbol: {0} ++++++++++++++++++++]\n".format(s.name)

    for i in range(3):
        print repr(s.specialize())


## Step 8
print "Protocol Grammer Modelling and Inference Phase"
try:
    input("Press enter to continue")
except SyntaxError:
    pass

print "\n[++++++++++++++++++++ Step 8 --> Create the automata, generate trafic and send it to the server ++++++++++++++++++++]\n"

# Create a session of messages
msgs_session3 = PCAPImporter.readFile("/home/lenz/COMP588/PRE/Project/projects/target_src_v1_session3.pcap").values()

session1 = Session(msgs_session1)
session2 = Session(msgs_session2)
session3 = Session(msgs_session3)

# Abstract this session according to the infered symbols
abstractSession1 = session1.abstract(symbols.values())
abstractSession2 = session2.abstract(symbols.values())
abstractSession3 = session3.abstract(symbols.values())

# Generate an automata according to the observed sequence of messages/symbols
automata = Automata.generateChainedStatesAutomata(abstractSession1, symbols.values())
#automata = Automata.generateOneStateAutomata(abstractSession1, symbols.values())
#automata = Automata.generatePTAAutomata([abstractSession1, abstractSession3], symbols.values())

# Print the dot representation of the automata
dotcode = automata.generateDotCode()
print dotcode

# Create a UDP client instance
channelOut = UDPClient(remoteIP="127.0.0.1", remotePort=4242)
abstractionLayerOut = AbstractionLayer(channelOut, symbols.values())
abstractionLayerOut.openChannel()

# Visit the automata for n iteration
state = automata.initialState
for i in xrange(1):
    state = state.executeAsInitiator(abstractionLayerOut)


## Step 9
#try:
#    input("Press enter to continue")
#except SyntaxError:
#    pass

#print "\n[++++++++++++++++++++ Do some fuzzing on a specific symbol ++++++++++++++++++++]\n"
# print "/!\ If nothing happens, it's probably 'cause you didn't launch the 'target' server /!\\n"

#def send_and_receive_symbol(symbol):
#    data = symbol.specialize()
#    print "[+] Sending: {0}".format(repr(data))
#    channelOut.write(data)
#    data = channelOut.read()
#    print "[+] Receiving: {0}".format(repr(data))

# Update symbol definition to allow a broader payload size
#symbols["CMDidentify"].fields[2].fields[2].domain = Raw(nbBytes=(10, 126))

#for i in range(30):
#    send_and_receive_symbol(symbols["CMDidentify"])

#channelOut.close()

